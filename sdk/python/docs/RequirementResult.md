# RequirementResult

Individual requirement result

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**category** | **str** | Category | 
**id** | **str** | Requirement ID | 
**name** | **str** | Requirement name | 
**remediation** | **str** | Remediation guidance | [optional] 
**severity** | **str** | Severity | 
**status** | **str** | Status (pass, fail, warning) | 
**violation_count** | **int** | Number of violations | 
**violations** | [**List[ViolationDetail]**](ViolationDetail.md) | Violation details | [optional] 

## Example

```python
from cipherrun_client.models.requirement_result import RequirementResult

# TODO update the JSON string below
json = "{}"
# create an instance of RequirementResult from a JSON string
requirement_result_instance = RequirementResult.from_json(json)
# print the JSON string representation of the object
print(RequirementResult.to_json())

# convert the object into a dict
requirement_result_dict = requirement_result_instance.to_dict()
# create an instance of RequirementResult from a dict
requirement_result_from_dict = RequirementResult.from_dict(requirement_result_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


