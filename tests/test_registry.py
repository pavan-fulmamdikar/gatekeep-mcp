"""
tests/test_registry.py

Full test coverage for gatekeep/registry.py

Tests ToolDefinition, ToolRegistry, _build_json_schema,
_py_type_to_json, and all schema output formats.
"""

import pytest
from typing import List, Dict, Optional

from gatekeep.registry import (
    ToolDefinition,
    ToolRegistry,
    _build_json_schema,
    _py_type_to_json,
)


@pytest.fixture(autouse=True)
def clean_registry():
    ToolRegistry.reset()
    yield
    ToolRegistry.reset()


# ── _py_type_to_json ──────────────────────────────────────────────────────────

class TestPyTypeToJson:
    def test_str_maps_to_string(self):
        assert _py_type_to_json(str) == "string"

    def test_int_maps_to_integer(self):
        assert _py_type_to_json(int) == "integer"

    def test_float_maps_to_number(self):
        assert _py_type_to_json(float) == "number"

    def test_bool_maps_to_boolean(self):
        assert _py_type_to_json(bool) == "boolean"

    def test_list_maps_to_array(self):
        assert _py_type_to_json(list) == "array"

    def test_dict_maps_to_object(self):
        assert _py_type_to_json(dict) == "object"

    def test_list_generic_maps_to_array(self):
        assert _py_type_to_json(List[str]) == "array"

    def test_dict_generic_maps_to_object(self):
        assert _py_type_to_json(Dict[str, int]) == "object"

    def test_unknown_type_defaults_to_string(self):
        class CustomType:
            pass
        assert _py_type_to_json(CustomType) == "string"

    def test_none_defaults_to_string(self):
        assert _py_type_to_json(type(None)) == "string"


# ── _build_json_schema ────────────────────────────────────────────────────────

class TestBuildJsonSchema:
    def test_required_params_in_required_list(self):
        def fn(name: str, age: int) -> None:
            pass
        schema = _build_json_schema(fn)
        assert "name" in schema["required"]
        assert "age" in schema["required"]

    def test_optional_params_not_in_required(self):
        def fn(name: str, limit: int = 10) -> None:
            pass
        schema = _build_json_schema(fn)
        assert "name" in schema["required"]
        assert "limit" not in schema["required"]

    def test_optional_default_stored(self):
        def fn(limit: int = 25) -> None:
            pass
        schema = _build_json_schema(fn)
        assert schema["properties"]["limit"]["default"] == 25

    def test_schema_type_is_object(self):
        def fn(x: str) -> None:
            pass
        schema = _build_json_schema(fn)
        assert schema["type"] == "object"

    def test_schema_has_properties(self):
        def fn(x: str) -> None:
            pass
        schema = _build_json_schema(fn)
        assert "properties" in schema

    def test_self_param_excluded(self):
        def fn(self, name: str) -> None:
            pass
        schema = _build_json_schema(fn)
        assert "self" not in schema["properties"]

    def test_no_params_returns_empty_schema(self):
        def fn() -> None:
            pass
        schema = _build_json_schema(fn)
        assert schema["properties"] == {}
        assert schema["required"] == []

    def test_list_param_type(self):
        def fn(items: List[str]) -> None:
            pass
        schema = _build_json_schema(fn)
        assert schema["properties"]["items"]["type"] == "array"

    def test_dict_param_type(self):
        def fn(data: Dict[str, int]) -> None:
            pass
        schema = _build_json_schema(fn)
        assert schema["properties"]["data"]["type"] == "object"

    def test_function_without_type_hints_defaults_to_string(self):
        def fn(name, value):
            pass
        schema = _build_json_schema(fn)
        assert schema["properties"]["name"]["type"] == "string"
        assert schema["properties"]["value"]["type"] == "string"


# ── ToolDefinition ────────────────────────────────────────────────────────────

class TestToolDefinition:
    def _make_def(self, name="my_tool", desc="Does something useful"):
        def fn(x: str) -> str:
            return x
        return ToolDefinition(
            name=name,
            description=desc,
            parameters=_build_json_schema(fn),
            fn=fn,
            tags=("tag1",),
            version="1.0.0",
        )

    def test_name_stored(self):
        d = self._make_def(name="get_weather")
        assert d.name == "get_weather"

    def test_description_stored(self):
        d = self._make_def(desc="Get weather for a city")
        assert d.description == "Get weather for a city"

    def test_tags_stored(self):
        d = self._make_def()
        assert "tag1" in d.tags

    def test_fn_callable(self):
        d = self._make_def()
        assert callable(d.fn)

    def test_to_llm_schema_type_is_function(self):
        d = self._make_def()
        schema = d.to_llm_schema()
        assert schema["type"] == "function"

    def test_to_llm_schema_has_function_key(self):
        d = self._make_def()
        schema = d.to_llm_schema()
        assert "function" in schema

    def test_to_llm_schema_name_correct(self):
        d = self._make_def(name="get_order")
        schema = d.to_llm_schema()
        assert schema["function"]["name"] == "get_order"

    def test_to_llm_schema_has_description(self):
        d = self._make_def(desc="My description")
        schema = d.to_llm_schema()
        assert schema["function"]["description"] == "My description"

    def test_to_llm_schema_has_parameters(self):
        d = self._make_def()
        schema = d.to_llm_schema()
        assert "parameters" in schema["function"]

    def test_to_anthropic_schema_has_name(self):
        d = self._make_def(name="send_email")
        schema = d.to_anthropic_schema()
        assert schema["name"] == "send_email"

    def test_to_anthropic_schema_has_description(self):
        d = self._make_def(desc="Sends an email")
        schema = d.to_anthropic_schema()
        assert schema["description"] == "Sends an email"

    def test_to_anthropic_schema_has_input_schema(self):
        d = self._make_def()
        schema = d.to_anthropic_schema()
        assert "input_schema" in schema

    def test_to_anthropic_schema_no_type_field(self):
        d = self._make_def()
        schema = d.to_anthropic_schema()
        assert "type" not in schema

    def test_repr_contains_name(self):
        d = self._make_def(name="my_tool")
        assert "my_tool" in repr(d)

    def test_frozen_immutable(self):
        d = self._make_def()
        with pytest.raises((AttributeError, TypeError)):
            d.name = "new_name"  # type: ignore


# ── ToolRegistry ──────────────────────────────────────────────────────────────

class TestToolRegistry:
    def test_instance_returns_singleton(self):
        r1 = ToolRegistry.instance()
        r2 = ToolRegistry.instance()
        assert r1 is r2

    def test_reset_creates_new_instance(self):
        r1 = ToolRegistry.instance()
        ToolRegistry.reset()
        r2 = ToolRegistry.instance()
        assert r1 is not r2

    def test_register_stores_tool(self):
        registry = ToolRegistry.instance()
        def my_fn(x: str) -> str:
            """Does something."""
            return x
        registry.register(my_fn)
        assert "my_fn" in registry

    def test_register_custom_name(self):
        registry = ToolRegistry.instance()
        def my_fn(x: str) -> str:
            """Does something."""
            return x
        registry.register(my_fn, name="custom_name")
        assert "custom_name" in registry
        assert "my_fn" not in registry

    def test_register_custom_description(self):
        registry = ToolRegistry.instance()
        def my_fn(): pass
        registry.register(my_fn, description="Custom desc")
        defn = registry.get("my_fn")
        assert defn.description == "Custom desc"

    def test_register_falls_back_to_docstring(self):
        registry = ToolRegistry.instance()
        def my_fn():
            """Docstring description."""
            pass
        registry.register(my_fn)
        defn = registry.get("my_fn")
        assert defn.description == "Docstring description."

    def test_register_without_description_raises(self):
        registry = ToolRegistry.instance()
        def undocumented(): pass
        with pytest.raises(ValueError, match="no description"):
            registry.register(undocumented)

    def test_register_duplicate_raises(self):
        registry = ToolRegistry.instance()
        def fn_a():
            """Tool A."""
            pass
        registry.register(fn_a)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(fn_a)

    def test_get_returns_none_for_missing(self):
        registry = ToolRegistry.instance()
        assert registry.get("nonexistent") is None

    def test_get_all_returns_list(self):
        registry = ToolRegistry.instance()
        def fn_a():
            """A."""
            pass
        def fn_b():
            """B."""
            pass
        registry.register(fn_a)
        registry.register(fn_b)
        all_tools = registry.get_all()
        assert isinstance(all_tools, list)
        assert len(all_tools) == 2

    def test_names_returns_list_of_strings(self):
        registry = ToolRegistry.instance()
        def my_tool():
            """Tool."""
            pass
        registry.register(my_tool)
        assert "my_tool" in registry.names()

    def test_len_counts_tools(self):
        registry = ToolRegistry.instance()
        assert len(registry) == 0
        def t1():
            """T1."""
            pass
        def t2():
            """T2."""
            pass
        registry.register(t1)
        registry.register(t2)
        assert len(registry) == 2

    def test_contains_operator(self):
        registry = ToolRegistry.instance()
        def my_tool():
            """Tool."""
            pass
        registry.register(my_tool)
        assert "my_tool" in registry
        assert "not_registered" not in registry

    def test_register_with_tags(self):
        registry = ToolRegistry.instance()
        def my_fn():
            """Does stuff."""
            pass
        defn = registry.register(my_fn, tags=("crm", "email"))
        assert "crm" in defn.tags
        assert "email" in defn.tags

    def test_register_with_custom_version(self):
        registry = ToolRegistry.instance()
        def my_fn():
            """Does stuff."""
            pass
        defn = registry.register(my_fn, version="2.1.0")
        assert defn.version == "2.1.0"

    def test_register_with_custom_parameters(self):
        registry = ToolRegistry.instance()
        def my_fn(x): pass
        custom_schema = {
            "type": "object",
            "properties": {"x": {"type": "string", "description": "Custom"}},
            "required": ["x"],
        }
        defn = registry.register(my_fn, description="Custom schema fn", parameters=custom_schema)
        assert defn.parameters == custom_schema

    def test_repr_shows_tool_count(self):
        registry = ToolRegistry.instance()
        assert "0 tools" in repr(registry)

    def test_registry_empty_after_reset(self):
        registry = ToolRegistry.instance()
        def fn():
            """T."""
            pass
        registry.register(fn)
        assert len(registry) == 1
        ToolRegistry.reset()
        new_registry = ToolRegistry.instance()
        assert len(new_registry) == 0
