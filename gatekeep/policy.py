"""
gatekeep/policy.py

Deterministic Declarative Policy Evaluator for PreExecutionGate.
Safely evaluates AST-parsed declarative policy constraints on tool arguments
with sub-microsecond latency and zero eval() injection risks.

Supported syntax:
  - Comparisons: <, <=, >, >=, ==, !=, in, not in, is, is not
  - Boolean ops: and, or, not
  - Arithmetic: +, -, *, /, %
  - Argument resolution: amount, args.amount, args['amount']
  - Ledger references: ledger.has_requirement('order')
  - Built-in safe functions: len, str, int, float, lower, upper
"""

from __future__ import annotations

import ast
from typing import Any, Dict, Optional, Tuple


class PolicySyntaxError(Exception):
    """Raised when a policy expression contains invalid or unsafe syntax."""
    pass


class SafePolicyEvaluator:
    """
    Evaluates policy expressions using Python's AST without eval() or exec().
    Only pure comparison, arithmetic, and boolean expressions are permitted.
    """

    ALLOWED_FUNCTIONS = {
        "len": len,
        "str": str,
        "int": int,
        "float": float,
        "lower": lambda s: str(s).lower(),
        "upper": lambda s: str(s).upper(),
        "abs": abs,
    }

    def __init__(self, expression: str) -> None:
        self.expression = expression.strip()
        try:
            self._tree = ast.parse(self.expression, mode="eval")
        except SyntaxError as e:
            raise PolicySyntaxError(f"Invalid policy expression syntax: {e}") from e
        self._validate_ast(self._tree.body)

    def _validate_ast(self, node: ast.AST) -> None:
        """Ensure the AST only contains safe, declarative constructs."""
        allowed_nodes = (
            ast.Expression,
            ast.BoolOp,
            ast.BinOp,
            ast.UnaryOp,
            ast.Compare,
            ast.Name,
            ast.Constant,
            ast.Attribute,
            ast.Subscript,
            ast.Index if hasattr(ast, "Index") else type(None),
            ast.List,
            ast.Tuple,
            ast.Set,
            ast.Dict,
            ast.Call,
            # Operators
            ast.And, ast.Or, ast.Not,
            ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod,
            ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
            ast.In, ast.NotIn, ast.Is, ast.IsNot,
            ast.Load
        )

        for child in ast.walk(node):
            if not isinstance(child, allowed_nodes):
                raise PolicySyntaxError(
                    f"Forbidden syntax construct in policy: {type(child).__name__}"
                )
            if isinstance(child, ast.Call):
                # Only allow specific safe functions or ledger helper calls
                if isinstance(child.func, ast.Name):
                    if child.func.id not in self.ALLOWED_FUNCTIONS:
                        raise PolicySyntaxError(
                            f"Call to unauthorized function: '{child.func.id}'"
                        )
                elif isinstance(child.func, ast.Attribute):
                    # Allow ledger methods: has_requirement, has_seen_entity, etc.
                    if child.func.attr not in (
                        "has_requirement", "has_seen_entity", "get", "lower", "upper", "strip"
                    ):
                        raise PolicySyntaxError(
                            f"Call to unauthorized attribute method: '{child.func.attr}'"
                        )
                else:
                    raise PolicySyntaxError("Unsupported function call in policy.")

    def evaluate(self, arguments: Dict[str, Any], ledger: Optional[Any] = None) -> Tuple[bool, str]:
        """
        Evaluate the policy against the tool arguments and optional ledger.
        Returns (True, "") on success, or (False, reason) on policy violation.
        """
        # Build evaluation context
        ctx = dict(arguments)
        ctx["args"] = arguments
        ctx["arguments"] = arguments
        ctx["ledger"] = ledger

        try:
            val = self._eval_node(self._tree.body, ctx)
            passed = bool(val)
            if passed:
                return True, ""
            return False, f"Policy constraint '{self.expression}' evaluated to False for arguments {arguments}."
        except Exception as e:
            return False, f"Policy evaluation error on '{self.expression}': {str(e)}"

    def _eval_node(self, node: ast.AST, ctx: Dict[str, Any]) -> Any:
        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            if node.id in ctx:
                return ctx[node.id]
            if node.id in self.ALLOWED_FUNCTIONS:
                return self.ALLOWED_FUNCTIONS[node.id]
            # If variable not present in args, return None
            return None

        if isinstance(node, ast.Attribute):
            val = self._eval_node(node.value, ctx)
            if val is None:
                return None
            if isinstance(val, dict):
                return val.get(node.attr)
            return getattr(val, node.attr, None)

        if isinstance(node, ast.Subscript):
            val = self._eval_node(node.value, ctx)
            key = self._eval_node(node.slice, ctx)
            if val is None or key is None:
                return None
            try:
                return val[key]
            except (KeyError, IndexError, TypeError):
                return None

        if isinstance(node, ast.UnaryOp):
            operand = self._eval_node(node.operand, ctx)
            if isinstance(node.op, ast.Not):
                return not operand
            if isinstance(node.op, ast.UAdd):
                return +operand
            if isinstance(node.op, ast.USub):
                return -operand

        if isinstance(node, ast.BinOp):
            left = self._eval_node(node.left, ctx)
            right = self._eval_node(node.right, ctx)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left / right
            if isinstance(node.op, ast.Mod):
                return left % right

        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                for val_node in node.values:
                    if not self._eval_node(val_node, ctx):
                        return False
                return True
            if isinstance(node.op, ast.Or):
                for val_node in node.values:
                    if self._eval_node(val_node, ctx):
                        return True
                return False

        if isinstance(node, ast.Compare):
            left = self._eval_node(node.left, ctx)
            for op, comparator_node in zip(node.ops, node.comparators):
                right = self._eval_node(comparator_node, ctx)
                if isinstance(op, ast.Eq) and not (left == right):
                    return False
                elif isinstance(op, ast.NotEq) and not (left != right):
                    return False
                elif isinstance(op, ast.Lt) and not (left < right):
                    return False
                elif isinstance(op, ast.LtE) and not (left <= right):
                    return False
                elif isinstance(op, ast.Gt) and not (left > right):
                    return False
                elif isinstance(op, ast.GtE) and not (left >= right):
                    return False
                elif isinstance(op, ast.In) and not (left in right):
                    return False
                elif isinstance(op, ast.NotIn) and not (left not in right):
                    return False
                elif isinstance(op, ast.Is) and not (left is right):
                    return False
                elif isinstance(op, ast.IsNot) and not (left is not right):
                    return False
                left = right
            return True

        if isinstance(node, ast.List):
            return [self._eval_node(elt, ctx) for elt in node.elts]

        if isinstance(node, ast.Tuple):
            return tuple(self._eval_node(elt, ctx) for elt in node.elts)

        if isinstance(node, ast.Set):
            return {self._eval_node(elt, ctx) for elt in node.elts}

        if isinstance(node, ast.Dict):
            return {
                self._eval_node(k, ctx): self._eval_node(v, ctx)
                for k, v in zip(node.keys, node.values)
            }

        if isinstance(node, ast.Call):
            func = self._eval_node(node.func, ctx)
            args = [self._eval_node(a, ctx) for a in node.args]
            kwargs = {kw.arg: self._eval_node(kw.value, ctx) for kw in node.keywords}
            if callable(func):
                return func(*args, **kwargs)
            return None

        raise PolicySyntaxError(f"Unhandled node in policy evaluation: {type(node).__name__}")


_POLICY_CACHE: Dict[str, SafePolicyEvaluator] = {}


def evaluate_declarative_policy(
    policy_expr: str,
    arguments: Dict[str, Any],
    ledger: Optional[Any] = None,
) -> Tuple[bool, str]:
    """
    Safely evaluate a declarative policy expression against tool arguments and session ledger.
    Cached across calls for sub-microsecond performance.
    """
    expr = policy_expr.strip()
    if not expr:
        return True, ""

    evaluator = _POLICY_CACHE.get(expr)
    if evaluator is None:
        evaluator = SafePolicyEvaluator(expr)
        _POLICY_CACHE[expr] = evaluator

    return evaluator.evaluate(arguments, ledger=ledger)
