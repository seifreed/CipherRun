"""Exercise generated endpoint wrappers without making network requests."""

import inspect
import types
import typing
from types import SimpleNamespace
from unittest.mock import Mock
from enum import Enum

import cipherrun_client.api as generated_api
import cipherrun_client.models as generated_models
from cipherrun_client.api_client import ApiClient


class RawResponse:
    response = None

    def __init__(self):
        self.response = self

    def read(self):
        return b"{}"


def _argument_for(parameter):
    if parameter.name == "_host_index":
        return 0
    if parameter.name == "_request_timeout":
        return 1.0
    if parameter.name in {"_request_auth", "_headers"}:
        return {}
    if parameter.name == "_content_type":
        return "application/json"

    annotation = parameter.annotation
    while True:
        origin = typing.get_origin(annotation)
        arguments = typing.get_args(annotation)
        if origin is typing.Annotated:
            annotation = arguments[0]
            continue
        if origin in (typing.Union, types.UnionType):
            annotation = next(
                (item for item in arguments if item is not type(None)), type(None)
            )
            continue
        break
    if origin is typing.Literal:
        return arguments[0]
    if origin in (list, typing.List):
        return []
    if origin in (dict, typing.Dict):
        return {}
    if annotation is str:
        return "coverage-fixture"
    if annotation is int:
        return 1
    if annotation is float:
        return 1.0
    if annotation is bool:
        return True
    if inspect.isclass(annotation) and issubclass(annotation, Enum):
        return next(iter(annotation))
    if inspect.isclass(annotation) and hasattr(annotation, "model_construct"):
        return annotation.model_construct()
    return None


def test_all_generated_endpoints_support_decoded_and_raw_responses():
    model_arguments = {
        "create_credential_request": generated_models.CreateCredentialRequest,
        "rotate_credential_request": generated_models.RotateCredentialRequest,
        "policy_request": generated_models.PolicyRequest,
        "policy_evaluation_request": generated_models.PolicyEvaluationRequest,
        "scan_request": generated_models.ScanRequest,
    }
    exercised = 0

    for name, api_type in vars(generated_api).items():
        if not inspect.isclass(api_type) or not name.endswith("Api"):
            continue

        api_client = ApiClient()
        api_client.call_api = Mock(side_effect=lambda *args, **kwargs: RawResponse())
        api_client.response_deserialize = Mock(
            return_value=SimpleNamespace(data={"fixture": "response"})
        )
        api = api_type(api_client)

        for method_name in dir(api):
            if not method_name.endswith("_with_http_info"):
                continue

            api.api_client.call_api.reset_mock()
            api.api_client.response_deserialize.reset_mock()
            method = getattr(api, method_name)
            arguments = {}
            all_arguments = {}
            for parameter in inspect.signature(method).parameters.values():
                if parameter.default is not inspect.Parameter.empty:
                    all_arguments[parameter.name] = _argument_for(parameter)
                    continue
                model_type = model_arguments.get(parameter.name)
                value = model_type.model_construct() if model_type else "coverage-fixture"
                arguments[parameter.name] = value
                all_arguments[parameter.name] = value

            endpoint = method_name.removesuffix("_with_http_info")
            assert getattr(api, endpoint)(**arguments) == {"fixture": "response"}
            assert api.api_client.call_api.call_count == 1
            assert api.api_client.response_deserialize.call_count == 1

            api.api_client.call_api.reset_mock()
            api.api_client.response_deserialize.reset_mock()
            response = method(**all_arguments)
            assert response.data == {"fixture": "response"}
            assert api.api_client.call_api.call_count == 1
            assert api.api_client.response_deserialize.call_count == 1

            api.api_client.call_api.reset_mock()
            api.api_client.response_deserialize.reset_mock()
            raw_method = getattr(api, f"{endpoint}_without_preload_content")
            raw_response = raw_method(**all_arguments)
            assert isinstance(raw_response, RawResponse)
            assert api.api_client.call_api.call_count == 1
            exercised += 1

    assert exercised >= 19
