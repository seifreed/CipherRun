# cipherrun_client.StatsApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_stats**](StatsApi.md#get_stats) | **GET** /api/v1/stats | Get API statistics


# **get_stats**
> StatsResponse get_stats()

Get API statistics

Returns overall API usage and scan statistics

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.stats_response import StatsResponse
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
    api_instance = cipherrun_client.StatsApi(api_client)

    try:
        # Get API statistics
        api_response = api_instance.get_stats()
        print("The response of StatsApi->get_stats:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling StatsApi->get_stats: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**StatsResponse**](StatsResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | API statistics |  -  |
**500** | Failed to load statistics from configured dependencies |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

