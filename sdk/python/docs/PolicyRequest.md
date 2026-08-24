# PolicyRequest

Policy creation/update request

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**description** | **str** | Policy description | [optional] 
**enabled** | **bool** | Policy enabled | [optional] 
**name** | **str** | Policy name | 
**rules** | **str** | Policy rules in YAML format | 

## Example

```python
from cipherrun_client.models.policy_request import PolicyRequest

# TODO update the JSON string below
json = "{}"
# create an instance of PolicyRequest from a JSON string
policy_request_instance = PolicyRequest.from_json(json)
# print the JSON string representation of the object
print(PolicyRequest.to_json())

# convert the object into a dict
policy_request_dict = policy_request_instance.to_dict()
# create an instance of PolicyRequest from a dict
policy_request_from_dict = PolicyRequest.from_dict(policy_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


