# PolicyCheckResult

Individual policy check result

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**actual** | **str** | Actual value | [optional] 
**check** | **str** | Check name | 
**expected** | **str** | Expected value | [optional] 
**message** | **str** | Failure message if not passed | [optional] 
**passed** | **bool** | Check passed | 
**severity** | **str** | Severity level | 

## Example

```python
from cipherrun_client.models.policy_check_result import PolicyCheckResult

# TODO update the JSON string below
json = "{}"
# create an instance of PolicyCheckResult from a JSON string
policy_check_result_instance = PolicyCheckResult.from_json(json)
# print the JSON string representation of the object
print(PolicyCheckResult.to_json())

# convert the object into a dict
policy_check_result_dict = policy_check_result_instance.to_dict()
# create an instance of PolicyCheckResult from a dict
policy_check_result_from_dict = PolicyCheckResult.from_dict(policy_check_result_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


