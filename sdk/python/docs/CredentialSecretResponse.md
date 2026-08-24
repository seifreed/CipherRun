# CredentialSecretResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**credential** | [**CredentialView**](CredentialView.md) |  | 
**secret** | **str** | Returned only once during create/rotate; never persisted in API output. | 

## Example

```python
from cipherrun_client.models.credential_secret_response import CredentialSecretResponse

# TODO update the JSON string below
json = "{}"
# create an instance of CredentialSecretResponse from a JSON string
credential_secret_response_instance = CredentialSecretResponse.from_json(json)
# print the JSON string representation of the object
print(CredentialSecretResponse.to_json())

# convert the object into a dict
credential_secret_response_dict = credential_secret_response_instance.to_dict()
# create an instance of CredentialSecretResponse from a dict
credential_secret_response_from_dict = CredentialSecretResponse.from_dict(credential_secret_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


