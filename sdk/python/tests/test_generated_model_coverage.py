"""Exercise generated model serialization and nullable-field behavior."""

import datetime
import decimal
import inspect
import types
import typing
from enum import Enum

from pydantic import BaseModel, ValidationError

import cipherrun_client.models as generated_models


def _value_for(annotation, parents=()):
    origin = typing.get_origin(annotation)
    arguments = typing.get_args(annotation)
    if origin is typing.Annotated:
        return _value_for(arguments[0], parents)
    if origin in (typing.Union, types.UnionType):
        selected = next((item for item in arguments if item is not type(None)), type(None))
        return _value_for(selected, parents)
    if origin in (list, typing.List):
        return [_value_for(arguments[0], parents)] if arguments else []
    if origin in (dict, typing.Dict):
        return {"fixture": _value_for(arguments[-1], parents)} if len(arguments) > 1 else {}
    if origin in (tuple, typing.Tuple):
        return tuple(_value_for(item, parents) for item in arguments if item is not Ellipsis)
    if annotation is str:
        return "fixture"
    if annotation is int:
        return 1
    if annotation is float:
        return 1.0
    if annotation is bool:
        return True
    if annotation is bytes:
        return b"fixture"
    if annotation is datetime.date:
        return datetime.date(2026, 1, 1)
    if annotation is datetime.datetime:
        return datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    if annotation is decimal.Decimal:
        return decimal.Decimal("1")
    if inspect.isclass(annotation) and issubclass(annotation, Enum):
        return next(iter(annotation))
    if inspect.isclass(annotation) and issubclass(annotation, BaseModel):
        if annotation in parents:
            return None
        return _model_instance(annotation, parents)
    return None


def _model_instance(model_type, parents=(), nullable=False):
    values = {}
    fields_set = set()
    parents = (*parents, model_type)
    for name, field in model_type.model_fields.items():
        if nullable and not field.is_required():
            values[name] = None
        else:
            values[name] = _value_for(field.annotation, parents)
        fields_set.add(name)
    return model_type.model_construct(_fields_set=fields_set, **values)


def test_all_generated_models_round_trip_and_cover_nullable_fields():
    model_types = [
        value
        for value in vars(generated_models).values()
        if inspect.isclass(value)
        and value.__module__.startswith("cipherrun_client.models.")
        and issubclass(value, BaseModel)
    ]

    assert len(model_types) >= 27
    for model_type in model_types:
        model = _model_instance(model_type)
        assert isinstance(model.to_dict(), dict)
        assert model_type.from_json(model.to_json()) is not None
        assert model_type.from_dict(model.to_dict()) is not None
        assert model_type.from_dict(None) is None
        try:
            model_type.from_dict([])
        except ValidationError:
            pass
        else:
            raise AssertionError(f"{model_type.__name__} accepted a non-object input")
        assert model.to_str()

        nullable_model = _model_instance(model_type, nullable=True)
        nullable_model.to_dict()


def test_generated_enums_parse_json():
    enum_types = [
        value
        for value in vars(generated_models).values()
        if inspect.isclass(value)
        and value.__module__.startswith("cipherrun_client.models.")
        and issubclass(value, Enum)
        and hasattr(value, "from_json")
    ]

    assert enum_types
    for enum_type in enum_types:
        assert enum_type.from_json(f'"{next(iter(enum_type)).value}"') is next(iter(enum_type))
