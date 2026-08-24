# PolicyEvaluationResponse

Policy evaluation result

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**checks** | [**List[PolicyCheckResult]**](PolicyCheckResult.md) | Individual check results | 
**compliant** | **bool** | Overall compliance status | 
**evaluated_at** | **datetime** | Evaluation timestamp | 
**policy_id** | **str** | Policy ID | 
**policy_name** | **str** | Policy name | 
**scan_id** | **str** | Scan used for evaluation | 
**target** | **str** | Target evaluated | 

## Example

```python
from cipherrun_client.models.policy_evaluation_response import PolicyEvaluationResponse

# TODO update the JSON string below
json = "{}"
# create an instance of PolicyEvaluationResponse from a JSON string
policy_evaluation_response_instance = PolicyEvaluationResponse.from_json(json)
# print the JSON string representation of the object
print(PolicyEvaluationResponse.to_json())

# convert the object into a dict
policy_evaluation_response_dict = policy_evaluation_response_instance.to_dict()
# create an instance of PolicyEvaluationResponse from a dict
policy_evaluation_response_from_dict = PolicyEvaluationResponse.from_dict(policy_evaluation_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


