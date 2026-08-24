# ViolationDetail

Violation detail

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**evidence** | **str** | Evidence | [optional] 
**message** | **str** | Violation message | 
**rule_type** | **str** | Rule type that was violated | 

## Example

```python
from cipherrun_client.models.violation_detail import ViolationDetail

# TODO update the JSON string below
json = "{}"
# create an instance of ViolationDetail from a JSON string
violation_detail_instance = ViolationDetail.from_json(json)
# print the JSON string representation of the object
print(ViolationDetail.to_json())

# convert the object into a dict
violation_detail_dict = violation_detail_instance.to_dict()
# create an instance of ViolationDetail from a dict
violation_detail_from_dict = ViolationDetail.from_dict(violation_detail_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


