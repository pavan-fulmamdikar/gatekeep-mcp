"""
tests/test_decorator.py

Tests for @slim_tool decorator and ToolRegistry.
All tests reset the global registry so they don't interfere with each other.
"""

import pytest

from gatekeep.decorator import slim_tool
from gatekeep.registry import ToolRegistry, ToolDefinition


@pytest.fixture(autouse=True)
def clean_registry():
    """Reset the global ToolRegistry before and after every test."""
    ToolRegistry.reset()
    yield
    ToolRegistry.reset()


# ── Registration ──────────────────────────────────────────────────────────────

def test_bare_decorator_registers_tool():
    @slim_tool
    def fetch_order(order_id: str) -> dict:
        """Fetch order details by order ID."""
        return {}

    registry = ToolRegistry.instance()
    assert "fetch_order" in registry
    assert len(registry) == 1


def test_decorator_with_description():
    @slim_tool(description="Custom description for the tool")
    def my_tool(x: int) -> str:
        return str(x)

    definition = ToolRegistry.instance().get("my_tool")
    assert definition is not None
    assert definition.description == "Custom description for the tool"


def test_decorator_falls_back_to_docstring():
    @slim_tool
    def my_tool(x: int) -> str:
        """This is the docstring description."""
        return str(x)

    definition = ToolRegistry.instance().get("my_tool")
    assert definition.description == "This is the docstring description."


def test_decorator_raises_without_description():
    with pytest.raises(ValueError, match="no description"):
        @slim_tool
        def undocumented():
            pass


def test_decorator_custom_name():
    @slim_tool(description="Does something", name="custom_name")
    def original_name():
        pass

    registry = ToolRegistry.instance()
    assert "custom_name" in registry
    assert "original_name" not in registry


def test_decorator_tags_stored():
    @slim_tool(description="Sends an email", tags=["comms", "email"])
    def send_email(to: str) -> bool:
        return True

    defn = ToolRegistry.instance().get("send_email")
    assert "comms" in defn.tags
    assert "email" in defn.tags


def test_duplicate_registration_raises():
    @slim_tool(description="First registration")
    def my_tool():
        pass

    with pytest.raises(ValueError, match="already registered"):
        @slim_tool(description="Second registration")
        def my_tool():
            pass


def test_function_still_callable_after_decoration():
    @slim_tool(description="Adds two numbers together")
    def add(a: int, b: int) -> int:
        return a + b

    assert add(2, 3) == 5


def test_slim_tool_attribute_attached():
    @slim_tool(description="Does X")
    def my_fn():
        pass

    assert hasattr(my_fn, "_slim_tool")
    assert isinstance(my_fn._slim_tool, ToolDefinition)


# ── Schema generation ─────────────────────────────────────────────────────────

def test_json_schema_required_params():
    @slim_tool(description="Get stock price for a ticker")
    def get_stock(ticker: str, exchange: str) -> float:
        return 0.0

    defn = ToolRegistry.instance().get("get_stock")
    schema = defn.parameters
    assert "ticker" in schema["required"]
    assert "exchange" in schema["required"]


def test_json_schema_optional_params():
    @slim_tool(description="Search products with optional limit")
    def search(query: str, limit: int = 10) -> list:
        return []

    defn = ToolRegistry.instance().get("search")
    schema = defn.parameters
    assert "query" in schema["required"]
    assert "limit" not in schema["required"]
    assert schema["properties"]["limit"]["default"] == 10


def test_to_llm_schema_openai_format():
    @slim_tool(description="Get order status by ID")
    def get_order(order_id: str) -> dict:
        return {}

    defn = ToolRegistry.instance().get("get_order")
    llm_schema = defn.to_llm_schema()
    assert llm_schema["type"] == "function"
    assert llm_schema["function"]["name"] == "get_order"
    assert "description" in llm_schema["function"]
    assert "parameters" in llm_schema["function"]


def test_to_anthropic_schema_format():
    @slim_tool(description="Refund a transaction by ID")
    def refund(txn_id: str, amount: float) -> bool:
        return True

    defn = ToolRegistry.instance().get("refund")
    schema = defn.to_anthropic_schema()
    assert schema["name"] == "refund"
    assert "input_schema" in schema
    assert "description" in schema


# ── Registry operations ───────────────────────────────────────────────────────

def test_registry_get_all():
    @slim_tool(description="Tool A")
    def tool_a(): pass

    @slim_tool(description="Tool B")
    def tool_b(): pass

    all_tools = ToolRegistry.instance().get_all()
    names = [t.name for t in all_tools]
    assert "tool_a" in names
    assert "tool_b" in names


def test_registry_names():
    @slim_tool(description="Tool C")
    def tool_c(): pass

    assert "tool_c" in ToolRegistry.instance().names()


def test_registry_contains():
    @slim_tool(description="Exists check")
    def exists_tool(): pass

    registry = ToolRegistry.instance()
    assert "exists_tool" in registry
    assert "nonexistent_tool" not in registry
