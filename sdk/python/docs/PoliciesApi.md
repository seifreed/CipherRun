# cipherrun_client.PoliciesApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_policy**](PoliciesApi.md#create_policy) | **POST** /api/v1/policies | Create or update policy
[**evaluate_policy**](PoliciesApi.md#evaluate_policy) | **POST** /api/v1/policies/{id}/evaluate | Evaluate policy
[**get_policy**](PoliciesApi.md#get_policy) | **GET** /api/v1/policies/{id} | Get policy


# **create_policy**
> PolicyResponse create_policy(policy_request)

Create or update policy

Creates a new policy or updates an existing one

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.policy_request import PolicyRequest
from cipherrun_client.models.policy_response import PolicyResponse
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
    api_instance = cipherrun_client.PoliciesApi(api_client)
    policy_request = cipherrun_client.PolicyRequest() # PolicyRequest | 

    try:
        # Create or update policy
        api_response = api_instance.create_policy(policy_request)
        print("The response of PoliciesApi->create_policy:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling PoliciesApi->create_policy: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **policy_request** | [**PolicyRequest**](PolicyRequest.md)|  | 

### Return type

[**PolicyResponse**](PolicyResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | Policy created |  -  |
**400** | Invalid policy |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **evaluate_policy**
> PolicyEvaluationResponse evaluate_policy(id, policy_evaluation_request)

Evaluate policy

Evaluates a target against a specific policy

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.policy_evaluation_request import PolicyEvaluationRequest
from cipherrun_client.models.policy_evaluation_response import PolicyEvaluationResponse
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
    api_instance = cipherrun_client.PoliciesApi(api_client)
    id = 'id_example' # str | Policy ID
    policy_evaluation_request = cipherrun_client.PolicyEvaluationRequest() # PolicyEvaluationRequest | 

    try:
        # Evaluate policy
        api_response = api_instance.evaluate_policy(id, policy_evaluation_request)
        print("The response of PoliciesApi->evaluate_policy:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling PoliciesApi->evaluate_policy: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **str**| Policy ID | 
 **policy_evaluation_request** | [**PolicyEvaluationRequest**](PolicyEvaluationRequest.md)|  | 

### Return type

[**PolicyEvaluationResponse**](PolicyEvaluationResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Policy evaluation result |  -  |
**400** | Invalid target or scan options |  -  |
**404** | Policy not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_policy**
> PolicyResponse get_policy(id)

Get policy

Returns details of a specific policy

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.policy_response import PolicyResponse
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
    api_instance = cipherrun_client.PoliciesApi(api_client)
    id = 'id_example' # str | Policy ID

    try:
        # Get policy
        api_response = api_instance.get_policy(id)
        print("The response of PoliciesApi->get_policy:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling PoliciesApi->get_policy: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **id** | **str**| Policy ID | 

### Return type

[**PolicyResponse**](PolicyResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Policy details |  -  |
**404** | Policy not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

