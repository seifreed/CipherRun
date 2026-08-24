# cipherrun_client.CertificatesApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_certificate**](CertificatesApi.md#get_certificate) | **GET** /api/v1/certificates/{fingerprint} | Get certificate details
[**list_certificates**](CertificatesApi.md#list_certificates) | **GET** /api/v1/certificates | List certificates


# **get_certificate**
> CertificateSummary get_certificate(fingerprint)

Get certificate details

Returns detailed information about a specific certificate

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.certificate_summary import CertificateSummary
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
    api_instance = cipherrun_client.CertificatesApi(api_client)
    fingerprint = 'fingerprint_example' # str | Certificate SHA-256 fingerprint

    try:
        # Get certificate details
        api_response = api_instance.get_certificate(fingerprint)
        print("The response of CertificatesApi->get_certificate:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling CertificatesApi->get_certificate: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **fingerprint** | **str**| Certificate SHA-256 fingerprint | 

### Return type

[**CertificateSummary**](CertificateSummary.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Certificate details |  -  |
**400** | Invalid fingerprint |  -  |
**404** | Certificate not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_certificates**
> CertificateListResponse list_certificates(limit=limit, offset=offset, sort=sort, hostname=hostname, expiring_within_days=expiring_within_days)

List certificates

Returns a paginated list of certificates from the inventory

### Example

* Api Key Authentication (api_key):

```python
import cipherrun_client
from cipherrun_client.models.certificate_list_response import CertificateListResponse
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
    api_instance = cipherrun_client.CertificatesApi(api_client)
    limit = 56 # int | Maximum number of results (optional)
    offset = 56 # int | Offset for pagination (optional)
    sort = 'sort_example' # str | Sort order (expiry_asc, expiry_desc, issued_asc, issued_desc) (optional)
    hostname = 'hostname_example' # str | Filter by hostname (optional)
    expiring_within_days = 56 # int | Filter by expiring within days (optional)

    try:
        # List certificates
        api_response = api_instance.list_certificates(limit=limit, offset=offset, sort=sort, hostname=hostname, expiring_within_days=expiring_within_days)
        print("The response of CertificatesApi->list_certificates:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling CertificatesApi->list_certificates: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **limit** | **int**| Maximum number of results | [optional] 
 **offset** | **int**| Offset for pagination | [optional] 
 **sort** | **str**| Sort order (expiry_asc, expiry_desc, issued_asc, issued_desc) | [optional] 
 **hostname** | **str**| Filter by hostname | [optional] 
 **expiring_within_days** | **int**| Filter by expiring within days | [optional] 

### Return type

[**CertificateListResponse**](CertificateListResponse.md)

### Authorization

[api_key](../README.md#api_key)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | Certificate list |  -  |
**400** | Invalid query parameters |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

