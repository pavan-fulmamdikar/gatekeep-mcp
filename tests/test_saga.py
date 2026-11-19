"""
tests/test_saga.py

Unit tests for the Saga Pattern & Automated Compensation / Rollback Engine.
"""

import pytest
from gatekeep.decorator import slim_tool
from gatekeep.registry import ToolRegistry
from gatekeep import (
    PreExecutionGate,
    ToolReturnLedger,
    Verdict,
    SagaCoordinator,
    RollbackSummary,
)


def test_saga_coordinator_lifo_rollback():
    """Verify that multiple steps rollback in strict LIFO order."""
    execution_order = []

    def undo_step_1(res):
        execution_order.append("undo_step_1")

    def undo_step_2(res):
        execution_order.append("undo_step_2")

    def undo_step_3(res):
        execution_order.append("undo_step_3")

    saga = SagaCoordinator()
    saga.record_forward_execution("step_1", {"x": 1}, {"id": 101}, on_rollback=undo_step_1)
    saga.record_forward_execution("step_2", {"x": 2}, {"id": 102}, on_rollback=undo_step_2)
    saga.record_forward_execution("step_3", {"x": 3}, {"id": 103}, on_rollback=undo_step_3)

    assert saga.pending_count == 3

    summary: RollbackSummary = saga.rollback()

    assert summary.success is True
    assert summary.total_steps == 3
    assert summary.compensated_steps == 3
    assert summary.failed_steps == 0
    # Strict LIFO: step 3 undone first, then step 2, then step 1
    assert execution_order == ["undo_step_3", "undo_step_2", "undo_step_1"]
    assert saga.pending_count == 0


def test_compensates_with_registry_tool():
    """Verify compensation using another registered tool in the ToolRegistry."""
    ToolRegistry.reset()
    reg = ToolRegistry.instance()

    destroyed_instances = []

    @slim_tool(
        description="Destroy a cloud virtual machine instance",
        mode="write"
    )
    def destroy_vm(instance_id: str):
        destroyed_instances.append(instance_id)
        return {"status": "destroyed"}

    @slim_tool(
        description="Create a cloud virtual machine instance",
        mode="write",
        compensates_with="destroy_vm",
        compensation_args=lambda res: {"instance_id": res["vm_id"]}
    )
    def create_vm(name: str):
        return {"status": "created", "vm_id": f"vm-{name}-999"}

    ledger = ToolReturnLedger()
    gate = PreExecutionGate(ledger=ledger, registry=reg)

    # 1. Simulate forward execution of create_vm
    create_res = create_vm("web-prod-1")
    ledger.absorb_tool_return(
        "create_vm",
        {"name": "web-prod-1"},
        create_res,
        mode="write",
        registry=reg
    )

    assert gate.saga.pending_count == 1

    # 2. Trigger rollback on gate
    summary = gate.rollback()
    assert summary.success is True
    assert summary.compensated_steps == 1
    assert destroyed_instances == ["vm-web-prod-1-999"]
    assert gate.saga.pending_count == 0

    # Verify audit receipt
    receipts = [r for r in gate.receipts if r.verdict == Verdict.ROLLBACK]
    assert len(receipts) == 1
    assert receipts[0].tool_name == "destroy_vm"


def test_saga_error_resilience():
    """Verify that a failure in one compensation step does not prevent remaining steps from rolling back."""
    compensated = []

    def failing_undo(res):
        raise RuntimeError("Network timeout contacting service")

    def successful_undo(res):
        compensated.append(res["id"])

    saga = SagaCoordinator()
    saga.record_forward_execution("step_1", {}, {"id": "res_1"}, on_rollback=successful_undo)
    saga.record_forward_execution("step_2", {}, {"id": "res_2"}, on_rollback=failing_undo)
    saga.record_forward_execution("step_3", {}, {"id": "res_3"}, on_rollback=successful_undo)

    summary = saga.rollback(stop_on_error=False)

    assert summary.success is False
    assert summary.total_steps == 3
    assert summary.compensated_steps == 2
    assert summary.failed_steps == 1
    # step_3 and step_1 should both have been compensated despite step_2's failure
    assert compensated == ["res_3", "res_1"]


def test_saga_commit_clears_stack():
    """Verify that commit() marks steps committed and leaves no pending compensations."""
    rolled_back = []

    def undo(res):
        rolled_back.append(res)

    saga = SagaCoordinator()
    saga.record_forward_execution("step_1", {}, {"ok": True}, on_rollback=undo)
    assert saga.pending_count == 1

    saga.commit()
    assert saga.pending_count == 0

    # Subsequent rollback does nothing since transaction committed
    summary = saga.rollback()
    assert summary.total_steps == 0
    assert len(rolled_back) == 0
