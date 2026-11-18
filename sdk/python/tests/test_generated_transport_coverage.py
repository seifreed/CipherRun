"""Exercise the generated client's transport, configuration, and error contracts."""

import copy
import datetime
import decimal
import json
import logging
import ssl
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

import pytest
import urllib3
from pydantic import SecretStr

from cipherrun_client.configuration import Configuration
from cipherrun_client.api_client import ApiClient
from cipherrun_client.exceptions import (
    ApiAttributeError,
    ApiException,
    ApiKeyError,
    ApiTypeError,
    ApiValueError,
    BadRequestException,
    ForbiddenException,
    NotFoundException,
    ServiceException,
    UnauthorizedException,
)
from cipherrun_client.rest import RESTClientObject, RESTResponse, is_socks_proxy_url


def _response(status=200, data=b"ok", headers=None):
    return SimpleNamespace(
        status=status,
        reason="reason",
        data=data,
        headers=headers or {"content-type": "text/plain"},
        getheaders=lambda: headers or {"content-type": "text/plain"},
    )


def _transport():
    client = object.__new__(RESTClientObject)
    client.pool_manager = Mock()
    client.pool_manager.request.return_value = _response()
    return client


@pytest.mark.parametrize("url, expected", [
    (None, False),
    ("localhost/path", False),
    ("https://proxy", False),
    ("SOCKS5H://proxy", True),
    ("socks4a://proxy", True),
])
def test_socks_proxy_detection(url, expected):
    assert is_socks_proxy_url(url) is expected


def test_rest_response_caches_data_and_exposes_headers():
    response = _response(headers={"x-id": "abc"})
    wrapped = RESTResponse(response)
    assert wrapped.read() == b"ok"
    response.data = b"changed"
    assert wrapped.read() == b"ok"
    assert wrapped.getheaders() == {"x-id": "abc"}
    assert wrapped.getheader("missing", "fallback") == "fallback"


@pytest.mark.parametrize("verify_ssl, expected", [(True, ssl.CERT_REQUIRED), (False, ssl.CERT_NONE)])
def test_transport_builds_pool_with_tls_and_proxy_options(verify_ssl, expected):
    config = Configuration()
    config.verify_ssl = verify_ssl
    config.assert_hostname = "api.example"
    config.retries = 2
    config.tls_server_name = "sni.example"
    config.socket_options = [(1, 2, 3)]
    config.connection_pool_maxsize = 7

    with patch("cipherrun_client.rest.urllib3.PoolManager") as pool:
        RESTClientObject(config)
        options = pool.call_args.kwargs
    assert options["cert_reqs"] == expected
    assert options["assert_hostname"] == "api.example"
    assert options["retries"] == 2
    assert options["server_hostname"] == "sni.example"
    assert options["socket_options"] == [(1, 2, 3)]
    assert options["maxsize"] == 7


def test_transport_selects_http_and_socks_proxy_managers():
    config = Configuration()
    config.proxy = "https://proxy.example"
    config.proxy_headers = {"Proxy-Authorization": "basic"}
    with patch("cipherrun_client.rest.urllib3.ProxyManager") as proxy_manager:
        RESTClientObject(config)
    assert proxy_manager.call_args.kwargs["proxy_url"] == config.proxy
    assert proxy_manager.call_args.kwargs["proxy_headers"] == config.proxy_headers

    config.proxy = "socks5h://proxy.example"
    socks_module = ModuleType("urllib3.contrib.socks")
    socks_module.SOCKSProxyManager = Mock()
    with patch.dict(sys.modules, {"urllib3.contrib.socks": socks_module}):
        RESTClientObject(config)
    assert socks_module.SOCKSProxyManager.call_args.kwargs["proxy_url"] == config.proxy
    assert socks_module.SOCKSProxyManager.call_args.kwargs["headers"] == config.proxy_headers


def test_rest_request_serializes_json_form_multipart_and_raw_bodies():
    client = _transport()
    response = client.request("post", "/", headers={"Content-Type": "application/json"}, body={"a": 1})
    assert response.read() == b"ok"
    assert client.pool_manager.request.call_args.kwargs["body"] == '{"a": 1}'

    client.request("POST", "/", headers={"Content-Type": "application/x-www-form-urlencoded"}, post_params={"a": "b"})
    assert client.pool_manager.request.call_args.kwargs["encode_multipart"] is False

    headers = {"Content-Type": "multipart/form-data"}
    client.request("POST", "/", headers=headers, post_params=[("a", {"b": 2})])
    assert "Content-Type" not in headers
    assert client.pool_manager.request.call_args.kwargs["fields"] == [("a", '{"b": 2}')]

    client.request("POST", "/", headers={"Content-Type": "application/octet-stream"}, body=b"raw")
    assert client.pool_manager.request.call_args.kwargs["body"] == b"raw"

    client.request("POST", "/", headers={"Content-Type": "text/plain"}, body=False)
    assert client.pool_manager.request.call_args.kwargs["body"] == "false"


def test_rest_request_handles_get_timeouts_bad_arguments_and_ssl_errors():
    client = _transport()
    client.request("GET", "/", _request_timeout=2)
    assert client.pool_manager.request.call_args.kwargs["timeout"].total == 2
    client.request("GET", "/", _request_timeout=(1, 3))
    assert client.pool_manager.request.call_args.kwargs["timeout"].connect_timeout == 1

    with pytest.raises(ApiValueError):
        client.request("POST", "/", body={"a": 1}, post_params={"b": 2})
    with pytest.raises(ApiException, match="Cannot prepare"):
        client.request("POST", "/", headers={"Content-Type": "application/xml"}, body={"a": 1})
    with pytest.raises(AssertionError):
        client.request("TRACE", "/")

    client.pool_manager.request.side_effect = urllib3.exceptions.SSLError("bad certificate")
    with pytest.raises(ApiException, match="SSLError"):
        client.request("GET", "/")


def test_exception_paths_response_mapping_and_rendering():
    errors = [
        ApiTypeError("type", ["item", 1], (str,), True),
        ApiValueError("value", ["item"]),
        ApiAttributeError("attribute", [0]),
        ApiKeyError("key", ["missing"]),
    ]
    assert [str(error) for error in errors] == [
        "type at ['item'][1]", "value at ['item']", "attribute at [0]", "\"key at ['missing']\""
    ]
    assert str(ApiTypeError("type")) == "type"
    assert str(ApiValueError("value")) == "value"
    assert str(ApiAttributeError("attribute")) == "attribute"
    assert str(ApiKeyError("key")) == "'key'"

    for status, error_type in [
        (400, BadRequestException), (401, UnauthorizedException),
        (403, ForbiddenException), (404, NotFoundException),
        (503, ServiceException), (302, ApiException),
    ]:
        with pytest.raises(error_type):
            ApiException.from_response(http_resp=_response(status), body="body", data={"detail": "error"})

    http_response = _response(500, headers={"x-id": "1"})
    exception = ApiException(http_resp=http_response)
    assert exception.headers == {"x-id": "1"}
    assert exception.body == "ok"
    assert "HTTP response headers" in str(exception)
    with pytest.raises(ApiException):
        ApiException.from_response(http_resp=_response(502), body=None, data=None)
    assert ApiException(http_resp=_response(data=object())).body is None
    assert "HTTP response body" in str(ApiException(500, "reason", body="failure"))


def test_configuration_copies_auth_defaults_and_host_variables(tmp_path):
    default = Configuration()
    Configuration.set_default(default)
    assert Configuration.get_default() is default
    assert Configuration.get_default_copy() is default

    config = Configuration(
        host="https://{region}.example",
        api_key={"api_key": "secret"},
        api_key_prefix={"api_key": "Token"},
        username="user",
        password="password",
        server_index=0,
        server_variables={"region": "eu"},
    )
    config.get_host_settings = lambda: [{
        "url": "https://{region}.example",
        "variables": {"region": {"default_value": "us", "enum_values": ["us", "eu"]}},
    }]
    assert config.host == "https://eu.example"
    assert config.get_api_key_with_prefix("api_key") == "Token secret"
    assert config.get_basic_auth_token().startswith("Basic ")
    assert config.logger_format == "%(asctime)s %(levelname)s %(message)s"
    config.logger_format = "%(levelname)s"
    assert config.logger_formatter.format(logging.LogRecord("x", 20, "", 1, "ok", (), None)) == "INFO"
    assert config.auth_settings()["api_key"]["key"] == "X-API-Key"
    assert "Python SDK Debug Report" in config.to_debug_report()
    default_hosts = Configuration()
    assert default_hosts.get_host_settings()[1]["url"] == "https://api.cipherrun.io"
    assert default_hosts.get_host_from_settings(1) == "https://api.cipherrun.io"
    assert config.get_host_from_settings(None) == config._base_path
    with pytest.raises(ValueError, match="Invalid index"):
        config.get_host_from_settings(4)
    with pytest.raises(ValueError, match="invalid value"):
        config.get_host_from_settings(0, {"region": "asia"})

    refreshed = []
    config.refresh_api_key_hook = lambda current: refreshed.append(current)
    config.get_api_key_with_prefix("missing", alias="api_key")
    assert refreshed == [config]

    config.logger_file = str(tmp_path / "sdk.log")
    clone = copy.deepcopy(config)
    assert clone.api_key == config.api_key
    assert clone.logger is not config.logger
    assert clone.logger["package_logger"] is config.logger["package_logger"]
    for logger in config.logger.values():
        logger.removeHandler(clone.logger_file_handler)
        logger.removeHandler(config.logger_file_handler)
    clone.logger_file_handler.close()
    config.logger_file_handler.close()
    Configuration.set_default(None)


def test_configuration_debug_property_and_empty_auth():
    config = Configuration(debug=False)
    assert config.get_api_key_with_prefix("absent") is None
    assert config.auth_settings() == {}
    original_levels = {logger: logger.level for logger in config.logger.values()}
    try:
        config.debug = True
        assert config.logger["package_logger"].level == logging.DEBUG
        config.debug = False
        assert all(logger.level == logging.WARNING for logger in config.logger.values())
    finally:
        for logger, level in original_levels.items():
            logger.setLevel(level)

    config.host = "https://override.example"
    assert config.host == "https://override.example"

    Configuration.set_default(None)


def test_api_client_defaults_context_and_header_helpers():
    original = ApiClient._default
    try:
        ApiClient.set_default(None)
        first = ApiClient.get_default()
        assert ApiClient.get_default() is first
        ApiClient.set_default(first)
        client = ApiClient(header_name="X-Test", header_value="value", cookie="sid=1")
        assert client.user_agent.startswith("OpenAPI-Generator/")
        client.user_agent = "test-agent"
        client.set_default_header("X-Extra", "yes")
        assert client.default_headers["X-Extra"] == "yes"
        with client as entered:
            assert entered is client
        assert client.__exit__(None, None, None) is None
        client.rest_client.request = Mock(return_value="response")
        assert client.call_api("GET", "/") == "response"
        client.rest_client.request.side_effect = ApiException(status=400)
        with pytest.raises(ApiException):
            client.call_api("GET", "/")
    finally:
        ApiClient.set_default(original)


def test_api_client_serialization_and_parameter_formats(tmp_path):
    client = ApiClient(Configuration(host="https://api.example"))
    from cipherrun_client.models import Permission
    from cipherrun_client.models import HealthResponse

    assert client.sanitize_for_serialization(None) is None
    assert client.sanitize_for_serialization(Permission.ADMIN) == Permission.ADMIN.value
    assert client.sanitize_for_serialization([decimal.Decimal("1.2"), (datetime.date(2026, 1, 2),)]) == [
        "1.2", ("2026-01-02",)
    ]
    assert client.sanitize_for_serialization(SimpleNamespace(value=3)) == {"value": 3}
    assert client.sanitize_for_serialization(
        HealthResponse.model_construct(status="ok", uptime_seconds=2, version="1")
    )["status"] == "ok"

    assert client.parameters_to_tuples({"items": [1, 2]}, {"items": "ssv"}) == [("items", "1 2")]
    assert client.parameters_to_tuples({"items": [1, 2]}, {"items": "tsv"}) == [("items", "1\t2")]
    assert client.parameters_to_tuples({"items": [1, 2]}, {"items": "pipes"}) == [("items", "1|2")]
    assert client.parameters_to_tuples({"items": [1, 2]}, {"items": "multi"}) == [("items", 1), ("items", 2)]
    assert client.parameters_to_tuples([("items", [1, 2])], {"items": "csv"}) == [("items", "1,2")]
    assert client.parameters_to_url_query({"enabled": True, "n": 2, "obj": {"a": 1}}, None) == (
        "enabled=true&n=2&obj=%7B%22a%22%3A%201%7D"
    )
    assert client.parameters_to_url_query({"items": ["a b", "c"]}, {"items": "multi"}) == "items=a b&items=c"
    assert client.parameters_to_url_query({"items": ["a b", "c"]}, {"items": "ssv"}) == "items=a%20b c"
    assert client.parameters_to_url_query({"items": ["a", "b"]}, {"items": "tsv"}) == "items=a\tb"
    assert client.parameters_to_url_query({"items": ["a", "b"]}, {"items": "pipes"}) == "items=a|b"
    assert client.parameters_to_url_query({"items": ["a", "b"]}, {"items": "csv"}) == "items=a,b"

    path = tmp_path / "test.txt"
    path.write_bytes(b"file data")
    assert client.files_parameters({"upload": str(path)})[0][1][:2] == ("test.txt", b"file data")
    assert client.files_parameters({"upload": b"raw"})[0][1][:2] == ("upload", b"raw")
    with pytest.raises(ValueError, match="Unsupported file value"):
        client.files_parameters({"upload": object()})
    assert client.select_header_accept([]) is None
    assert client.select_header_accept(["text/plain", "application/json"]) == "application/json"
    assert client.select_header_accept(["text/plain"]) == "text/plain"
    assert client.select_header_content_type([]) is None
    assert client.select_header_content_type(["text/plain", "application/json"]) == "application/json"
    assert client.select_header_content_type(["text/plain"]) == "text/plain"


def test_api_client_request_serialization_auth_and_deserialization(tmp_path):
    config = Configuration(host="https://api.example", api_key={"api_key": "token"})
    client = ApiClient(config)
    method, url, headers, body, post = client.param_serialize(
        "POST",
        "/items/{id}",
        path_params={"id": "a b"},
        query_params={"enabled": True},
        header_params={"X-Request": "yes"},
        body={"count": 1},
        post_params={"field": "value"},
        auth_settings=["api_key"],
        collection_formats=None,
        _host="https://alternate.example",
    )
    assert method == "POST"
    assert url == "https://alternate.example/items/a%20b?enabled=true"
    assert headers["X-API-Key"] == "token"
    assert "token" in headers.values()
    assert body == {"count": 1}
    assert post == [("field", "value")]

    headers = {}
    queries = []
    client.update_params_for_auth(headers, queries, ["missing"], "/", "GET", None)
    client.update_params_for_auth(headers, queries, None, "/", "GET", None)
    client.update_params_for_auth(headers, queries, ["custom"], "/", "GET", None,
                                  request_auth={"type": "api_key", "in": "query", "key": "key", "value": "v"})
    assert queries == [("key", "v")]
    client._apply_auth_params(headers, queries, "/", "GET", None,
                              {"type": "api_key", "in": "cookie", "value": "sid=1"})
    assert headers["Cookie"] == "sid=1"
    client._apply_auth_params(headers, queries, "/", "GET", None,
                              {"type": "http-signature", "in": "header", "key": "sig", "value": "x"})
    assert "sig" not in headers
    with pytest.raises(ApiValueError):
        client._apply_auth_params(headers, queries, "/", "GET", None, {"type": "api_key", "in": "body"})

    decoded = client.deserialize('{"value":1}', "object", "application/json")
    assert decoded == {"value": 1}
    assert client.deserialize("plain", "str", None) == "plain"
    assert client.deserialize('"text"', "str", "application/json") == "text"
    assert client.deserialize("plain", "str", "text/plain") == "plain"
    with pytest.raises(ApiException, match="Unsupported content type"):
        client.deserialize("x", "str", "application/xml")
    assert client.deserialize("", "str", "application/json") == ""
    assert client.deserialize("null", "object", "application/json") is None
    assert client.deserialize('["1", "2"]', "List[int]", "application/json") == [1, 2]
    assert client.deserialize('{"a": "1"}', "Dict[str, int]", "application/json") == {"a": 1}
    assert client.deserialize('"3.5"', "decimal", "application/json") == decimal.Decimal("3.5")
    assert client.deserialize('"2026-01-02"', "date", "application/json") == datetime.date(2026, 1, 2)
    assert client.deserialize('"2026-01-02T03:04:05Z"', "datetime", "application/json").year == 2026
    class TypeErrorCast:
        def __new__(cls, _):
            raise TypeError("invalid conversion")

    class UnicodeErrorCast:
        def __new__(cls, _):
            raise UnicodeEncodeError("ascii", "x", 0, 1, "invalid")

    assert client._ApiClient__deserialize_primitive("value", TypeErrorCast) == "value"
    assert client._ApiClient__deserialize_primitive("value", UnicodeErrorCast) == "value"

    response = RESTResponse(_response(data=b'{"ok":true}', headers={"content-type": "application/json"}))
    response.read()
    api_response = client.response_deserialize(response, {"2XX": "object"})
    assert api_response.data == {"ok": True}
    with pytest.raises(AssertionError, match=r"read\(\) must be called"):
        client.response_deserialize(RESTResponse(_response()), {})
    file_response = RESTResponse(_response(data=b"download", headers={"Content-Disposition": 'attachment; filename="report.txt"'}))
    file_response.read()
    client.configuration.temp_folder_path = str(tmp_path)
    downloaded = client.response_deserialize(file_response, {"200": "file"}).data
    assert open(downloaded, "rb").read() == b"download"


def test_api_client_files_headers_overrides_and_response_types(tmp_path):
    config = Configuration(host="https://api.example")
    config.ignore_operation_servers = True
    client = ApiClient(config, cookie="session=abc")
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"upload")
    _, url, headers, body, post = client.param_serialize(
        "POST", "/upload", header_params={}, files={"file": str(payload)},
        _host="https://ignored.example",
    )
    assert url == "https://api.example/upload"
    assert headers["Cookie"] == "session=abc"
    assert body is None
    assert post[0][0] == "file"

    from cipherrun_client.models import HealthResponse, Permission

    assert isinstance(client.sanitize_for_serialization(SecretStr("secret")), str)
    health = {"status": "ok", "uptime_seconds": 2, "version": "1"}
    assert client.deserialize(json.dumps(health), "HealthResponse", "application/json") == HealthResponse.from_dict(health)
    assert client.deserialize('"Admin"', "Permission", "application/json") is Permission.ADMIN
    with pytest.raises(ApiException, match="Failed to parse"):
        client.deserialize('"bad"', "Permission", "application/json")
    with pytest.raises(ApiException, match="Failed to parse.*date"):
        client.deserialize('"not-a-date"', "date", "application/json")
    with pytest.raises(ApiException, match="Failed to parse.*datetime"):
        client.deserialize('"not-a-date"', "datetime", "application/json")

    response = RESTResponse(_response(data=b"bytes"))
    response.read()
    assert client.response_deserialize(response, {"200": "bytearray"}).data == b"bytes"
    failed = RESTResponse(_response(status=400, data=b"bad"))
    failed.read()
    with pytest.raises(ApiException):
        client.response_deserialize(failed, {})

    with patch("cipherrun_client.api_client.parse", side_effect=ImportError):
        assert client.deserialize('"date"', "date", "application/json") == "date"
        assert client.deserialize('"datetime"', "datetime", "application/json") == "datetime"
    assert Configuration.get_default() is Configuration.get_default_copy()
    Configuration.set_default(None)
