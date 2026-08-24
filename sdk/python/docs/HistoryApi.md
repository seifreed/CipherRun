# cipherrun_client.HistoryApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_history**](HistoryApi.md#get_history) | **GET** /api/v1/history/{domain} | Get scan history


# **get_history**
> ScanHistoryResponse get_history(domain, port=port, limit=limit)

Get scan history

Returns scan history for a specific domain

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.scan_history_response import ScanHistoryResponse
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
    api_instance = cipherrun_client.HistoryApi(api_client)
    domain = 'domain_example' # str | Hostname or IP address
    port = 56 # int | Port number (default: 443, valid range: 1-65535) (optional)
    limit = 56 # int | Number of results (default: 10, min: 1, max: 1000) (optional)

    try:
        # Get scan history
        api_response = api_instance.get_history(domain, port=port, limit=limit)
        print("The response of HistoryApi->get_history:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling HistoryApi->get_history: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **domain** | **str**| Hostname or IP address | 
 **port** | **int**| Port number (default: 443, valid range: 1-65535) | [optional] 
 **limit** | **int**| Number of results (default: 10, min: 1, max: 1000) | [optional] 

### Return type

[**ScanHistoryResponse**](ScanHistoryResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Scan history |  -  |
**400** | Invalid query parameters |  -  |
**404** | No history found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

