# cipherrun_client.ComplianceApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**check_compliance**](ComplianceApi.md#check_compliance) | **GET** /api/v1/compliance/{framework} | Check compliance


# **check_compliance**
> ComplianceCheckResponse check_compliance(framework, target=target, format=format, detailed=detailed)

Check compliance

Runs a compliance check against a specific framework

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.compliance_check_response import ComplianceCheckResponse
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
    api_instance = cipherrun_client.ComplianceApi(api_client)
    framework = 'framework_example' # str | Compliance framework (pci-dss-v4, nist-sp800-52r2, etc.)
    target = 'target_example' # str | Target to check (hostname:port) (optional)
    format = 'format_example' # str | Output format (json, terminal, csv) (optional)
    detailed = True # bool | Include detailed requirement information (optional)

    try:
        # Check compliance
        api_response = api_instance.check_compliance(framework, target=target, format=format, detailed=detailed)
        print("The response of ComplianceApi->check_compliance:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling ComplianceApi->check_compliance: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **framework** | **str**| Compliance framework (pci-dss-v4, nist-sp800-52r2, etc.) | 
 **target** | **str**| Target to check (hostname:port) | [optional] 
 **format** | **str**| Output format (json, terminal, csv) | [optional] 
 **detailed** | **bool**| Include detailed requirement information | [optional] 

### Return type

[**ComplianceCheckResponse**](ComplianceCheckResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, text/plain, text/csv

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Compliance report |  -  |
**400** | Invalid framework or target |  -  |
**404** | Framework not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

