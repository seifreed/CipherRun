# RotateCredentialRequest


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**expires_at** | **datetime** |  | [optional] 

## Example

```python
from cipherrun_client.models.rotate_credential_request import RotateCredentialRequest

# TODO update the JSON string below
json = "{}"
# create an instance of RotateCredentialRequest from a JSON string
rotate_credential_request_instance = RotateCredentialRequest.from_json(json)
# print the JSON string representation of the object
print(RotateCredentialRequest.to_json())

# convert the object into a dict
rotate_credential_request_dict = rotate_credential_request_instance.to_dict()
# create an instance of RotateCredentialRequest from a dict
rotate_credential_request_from_dict = RotateCredentialRequest.from_dict(rotate_credential_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


