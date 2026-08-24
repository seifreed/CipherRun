# CreateCredentialRequest


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**expires_at** | **datetime** |  | [optional] 
**key_id** | **str** |  | 
**permission** | [**Permission**](Permission.md) |  | 
**principal_id** | **str** |  | 
**tenant_id** | **str** |  | [optional] 

## Example

```python
from cipherrun_client.models.create_credential_request import CreateCredentialRequest

# TODO update the JSON string below
json = "{}"
# create an instance of CreateCredentialRequest from a JSON string
create_credential_request_instance = CreateCredentialRequest.from_json(json)
# print the JSON string representation of the object
print(CreateCredentialRequest.to_json())

# convert the object into a dict
create_credential_request_dict = create_credential_request_instance.to_dict()
# create an instance of CreateCredentialRequest from a dict
create_credential_request_from_dict = CreateCredentialRequest.from_dict(create_credential_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


