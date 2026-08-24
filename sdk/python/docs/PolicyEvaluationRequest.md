# PolicyEvaluationRequest

Policy evaluation request

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**options** | [**ScanOptions**](ScanOptions.md) | Scan options | [optional] 
**target** | **str** | Target to evaluate | 

## Example

```python
from cipherrun_client.models.policy_evaluation_request import PolicyEvaluationRequest

# TODO update the JSON string below
json = "{}"
# create an instance of PolicyEvaluationRequest from a JSON string
policy_evaluation_request_instance = PolicyEvaluationRequest.from_json(json)
# print the JSON string representation of the object
print(PolicyEvaluationRequest.to_json())

# convert the object into a dict
policy_evaluation_request_dict = policy_evaluation_request_instance.to_dict()
# create an instance of PolicyEvaluationRequest from a dict
policy_evaluation_request_from_dict = PolicyEvaluationRequest.from_dict(policy_evaluation_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


