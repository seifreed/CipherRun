# CredentialView


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**active** | **bool** |  | 
**created_at** | **datetime** |  | 
**expires_at** | **datetime** |  | [optional] 
**key_id** | **str** |  | 
**permission** | [**Permission**](Permission.md) |  | 
**principal_id** | **str** |  | 
**tenant_id** | **str** |  | [optional] 

## Example

```python
from cipherrun_client.models.credential_view import CredentialView

# TODO update the JSON string below
json = "{}"
# create an instance of CredentialView from a JSON string
credential_view_instance = CredentialView.from_json(json)
# print the JSON string representation of the object
print(CredentialView.to_json())

# convert the object into a dict
credential_view_dict = credential_view_instance.to_dict()
# create an instance of CredentialView from a dict
credential_view_from_dict = CredentialView.from_dict(credential_view_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


