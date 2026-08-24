# cipherrun_client.CredentialsApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_credential**](CredentialsApi.md#create_credential) | **POST** /api/v1/credentials | Create a credential and return its one-time plaintext secret.
[**list_credentials**](CredentialsApi.md#list_credentials) | **GET** /api/v1/credentials | List credentials without exposing secret hashes.
[**revoke_credential**](CredentialsApi.md#revoke_credential) | **POST** /api/v1/credentials/{key_id}/revoke | Revoke a credential immediately.
[**rotate_credential**](CredentialsApi.md#rotate_credential) | **POST** /api/v1/credentials/{key_id}/rotate | Rotate a credential secret. The previous secret is invalid immediately.


# **create_credential**
> CredentialSecretResponse create_credential(create_credential_request)

Create a credential and return its one-time plaintext secret.

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.create_credential_request import CreateCredentialRequest
from cipherrun_client.models.credential_secret_response import CredentialSecretResponse
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
    api_instance = cipherrun_client.CredentialsApi(api_client)
    create_credential_request = cipherrun_client.CreateCredentialRequest() # CreateCredentialRequest | 

    try:
        # Create a credential and return its one-time plaintext secret.
        api_response = api_instance.create_credential(create_credential_request)
        print("The response of CredentialsApi->create_credential:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling CredentialsApi->create_credential: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **create_credential_request** | [**CreateCredentialRequest**](CreateCredentialRequest.md)|  | 

### Return type

[**CredentialSecretResponse**](CredentialSecretResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**201** | Credential created |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_credentials**
> List[CredentialView] list_credentials()

List credentials without exposing secret hashes.

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.credential_view import CredentialView
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
    api_instance = cipherrun_client.CredentialsApi(api_client)

    try:
        # List credentials without exposing secret hashes.
        api_response = api_instance.list_credentials()
        print("The response of CredentialsApi->list_credentials:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling CredentialsApi->list_credentials: %s\n" % e)
```



### Parameters

This endpoint does not need any parameter.

### Return type

[**List[CredentialView]**](CredentialView.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Credential metadata |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **revoke_credential**
> CredentialView revoke_credential(key_id)

Revoke a credential immediately.

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.credential_view import CredentialView
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
    api_instance = cipherrun_client.CredentialsApi(api_client)
    key_id = 'key_id_example' # str | Credential identifier

    try:
        # Revoke a credential immediately.
        api_response = api_instance.revoke_credential(key_id)
        print("The response of CredentialsApi->revoke_credential:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling CredentialsApi->revoke_credential: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_id** | **str**| Credential identifier | 

### Return type

[**CredentialView**](CredentialView.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Credential revoked |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **rotate_credential**
> CredentialSecretResponse rotate_credential(key_id, rotate_credential_request)

Rotate a credential secret. The previous secret is invalid immediately.

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.credential_secret_response import CredentialSecretResponse
from cipherrun_client.models.rotate_credential_request import RotateCredentialRequest
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
    api_instance = cipherrun_client.CredentialsApi(api_client)
    key_id = 'key_id_example' # str | Credential identifier
    rotate_credential_request = cipherrun_client.RotateCredentialRequest() # RotateCredentialRequest | 

    try:
        # Rotate a credential secret. The previous secret is invalid immediately.
        api_response = api_instance.rotate_credential(key_id, rotate_credential_request)
        print("The response of CredentialsApi->rotate_credential:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling CredentialsApi->rotate_credential: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_id** | **str**| Credential identifier | 
 **rotate_credential_request** | [**RotateCredentialRequest**](RotateCredentialRequest.md)|  | 

### Return type

[**CredentialSecretResponse**](CredentialSecretResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Credential rotated |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

