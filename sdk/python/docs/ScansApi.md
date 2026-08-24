# cipherrun_client.ScansApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**cancel_scan**](ScansApi.md#cancel_scan) | **DELETE** /api/v1/scan/{id} | Cancel a scan
[**create_scan**](ScansApi.md#create_scan) | **POST** /api/v1/scan | Create a new scan
[**create_stream_ticket**](ScansApi.md#create_stream_ticket) | **POST** /api/v1/scan/{id}/stream-ticket | 
[**get_scan_results**](ScansApi.md#get_scan_results) | **GET** /api/v1/scan/{id}/results | Get scan results
[**get_scan_status**](ScansApi.md#get_scan_status) | **GET** /api/v1/scan/{id} | Get scan status
[**websocket_handler**](ScansApi.md#websocket_handler) | **GET** /api/v1/scan/{id}/stream | WebSocket endpoint for scan progress


# **cancel_scan**
> cancel_scan(id)

Cancel a scan

Cancels a queued or running scan

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost:8080
# See configuration.py for a list of all supported configuration parameters.
configuration = cipherrun_client.Configuration(
    host = "http://localhost:8080"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

# Configure API key authorization: api_key
configuration.api_key['api_key'] = os.environ["API_KEY"]

# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['api_key'] = 'Bearer'

# Enter a context with an instance of the API client
with cipherrun_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = cipherrun_client.ScansApi(api_client)
    id = 'id_example' # str | Scan ID

    try:
        # Cancel a scan
        api_instance.cancel_scan(id)
    except Exception as e:
        print("Exception when calling ScansApi->cancel_scan: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **str**| Scan ID | 

### Return type

void (empty response body)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Scan cancelled |  -  |
**400** | Scan cannot be cancelled |  -  |
**404** | Scan not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_scan**
> ScanResponse create_scan(scan_request)

Create a new scan

Queues a new scan job and returns the scan ID

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.scan_request import ScanRequest
from cipherrun_client.models.scan_response import ScanResponse
from cipherrun_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost:8080
# See configuration.py for a list of all supported configuration parameters.
configuration = cipherrun_client.Configuration(
    host = "http://localhost:8080"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

# Configure API key authorization: api_key
configuration.api_key['api_key'] = os.environ["API_KEY"]

# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['api_key'] = 'Bearer'

# Enter a context with an instance of the API client
with cipherrun_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = cipherrun_client.ScansApi(api_client)
    scan_request = cipherrun_client.ScanRequest() # ScanRequest | 

    try:
        # Create a new scan
        api_response = api_instance.create_scan(scan_request)
        print("The response of ScansApi->create_scan:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ScansApi->create_scan: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **scan_request** | [**ScanRequest**](ScanRequest.md)|  | 

### Return type

[**ScanResponse**](ScanResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | Scan queued successfully |  -  |
**400** | Bad request |  -  |
**503** | Queue is full |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_stream_ticket**
> StreamTicketResponse create_stream_ticket(id)



### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.stream_ticket_response import StreamTicketResponse
from cipherrun_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost:8080
# See configuration.py for a list of all supported configuration parameters.
configuration = cipherrun_client.Configuration(
    host = "http://localhost:8080"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

# Configure API key authorization: api_key
configuration.api_key['api_key'] = os.environ["API_KEY"]

# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['api_key'] = 'Bearer'

# Enter a context with an instance of the API client
with cipherrun_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = cipherrun_client.ScansApi(api_client)
    id = 'id_example' # str | Scan ID

    try:
        api_response = api_instance.create_stream_ticket(id)
        print("The response of ScansApi->create_stream_ticket:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ScansApi->create_stream_ticket: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **str**| Scan ID | 

### Return type

[**StreamTicketResponse**](StreamTicketResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | One-use WebSocket ticket |  -  |
**404** | Scan not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_scan_results**
> object get_scan_results(id)

Get scan results

Returns the complete scan results for a completed scan

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost:8080
# See configuration.py for a list of all supported configuration parameters.
configuration = cipherrun_client.Configuration(
    host = "http://localhost:8080"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

# Configure API key authorization: api_key
configuration.api_key['api_key'] = os.environ["API_KEY"]

# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['api_key'] = 'Bearer'

# Enter a context with an instance of the API client
with cipherrun_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = cipherrun_client.ScansApi(api_client)
    id = 'id_example' # str | Scan ID

    try:
        # Get scan results
        api_response = api_instance.get_scan_results(id)
        print("The response of ScansApi->get_scan_results:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ScansApi->get_scan_results: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **str**| Scan ID | 

### Return type

**object**

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Scan results |  -  |
**400** | Scan not completed |  -  |
**404** | Scan not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_scan_status**
> ScanStatusResponse get_scan_status(id)

Get scan status

Returns the current status and progress of a scan

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.scan_status_response import ScanStatusResponse
from cipherrun_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost:8080
# See configuration.py for a list of all supported configuration parameters.
configuration = cipherrun_client.Configuration(
    host = "http://localhost:8080"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

# Configure API key authorization: api_key
configuration.api_key['api_key'] = os.environ["API_KEY"]

# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['api_key'] = 'Bearer'

# Enter a context with an instance of the API client
with cipherrun_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = cipherrun_client.ScansApi(api_client)
    id = 'id_example' # str | Scan ID

    try:
        # Get scan status
        api_response = api_instance.get_scan_status(id)
        print("The response of ScansApi->get_scan_status:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ScansApi->get_scan_status: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **str**| Scan ID | 

### Return type

[**ScanStatusResponse**](ScanStatusResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Scan status |  -  |
**404** | Scan not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **websocket_handler**
> websocket_handler(id)

WebSocket endpoint for scan progress

Streams real-time progress updates for a specific scan

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost:8080
# See configuration.py for a list of all supported configuration parameters.
configuration = cipherrun_client.Configuration(
    host = "http://localhost:8080"
)

# The client must configure the authentication and authorization parameters
# in accordance with the API server security policy.
# Examples for each auth method are provided below, use the example that
# satisfies your auth use case.

# Configure API key authorization: api_key
configuration.api_key['api_key'] = os.environ["API_KEY"]

# Uncomment below to setup prefix (e.g. Bearer) for API key, if needed
# configuration.api_key_prefix['api_key'] = 'Bearer'

# Enter a context with an instance of the API client
with cipherrun_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = cipherrun_client.ScansApi(api_client)
    id = 'id_example' # str | Scan ID

    try:
        # WebSocket endpoint for scan progress
        api_instance.websocket_handler(id)
    except Exception as e:
        print("Exception when calling ScansApi->websocket_handler: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **str**| Scan ID | 

### Return type

void (empty response body)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**101** | WebSocket connection established |  -  |
**404** | Scan not found |  -  |
**500** | Failed to access scan state |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

