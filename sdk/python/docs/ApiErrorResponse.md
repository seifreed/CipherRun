# ApiErrorResponse

API Error Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**details** | **str** | Optional details | [optional] 
**error** | **str** | Error code | 
**message** | **str** | Error message | 
**status** | **int** | HTTP status code | 

## Example

```python
from cipherrun_client.models.api_error_response import ApiErrorResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ApiErrorResponse from a JSON string
api_error_response_instance = ApiErrorResponse.from_json(json)
# print the JSON string representation of the object
print(ApiErrorResponse.to_json())

# convert the object into a dict
api_error_response_dict = api_error_response_instance.to_dict()
# create an instance of ApiErrorResponse from a dict
api_error_response_from_dict = ApiErrorResponse.from_dict(api_error_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


