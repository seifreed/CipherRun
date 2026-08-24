# ComplianceCheckResponse

Compliance check response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**disclaimer** | **str** | Scope limitation for external TLS posture checks | 
**evaluated_at** | **str** | Evaluation timestamp | 
**framework_id** | **str** | Framework ID | 
**framework_name** | **str** | Framework name | 
**framework_version** | **str** | Framework version | 
**requirements** | [**List[RequirementResult]**](RequirementResult.md) | Detailed requirement results | [optional] 
**rule_pack_sha256** | **str** | SHA-256 of the exact loaded rule pack YAML | [optional] 
**rule_pack_version** | **str** | Independently versioned CipherRun rule pack | [optional] 
**source_url** | **str** | Primary publication URL mapped by this pack | [optional] 
**source_version** | **str** | Primary publication version mapped by this pack | [optional] 
**status** | **str** | Overall compliance status | 
**summary** | [**ComplianceSummary**](ComplianceSummary.md) | Compliance summary | 
**target** | **str** | Target evaluated | 

## Example

```python
from cipherrun_client.models.compliance_check_response import ComplianceCheckResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ComplianceCheckResponse from a JSON string
compliance_check_response_instance = ComplianceCheckResponse.from_json(json)
# print the JSON string representation of the object
print(ComplianceCheckResponse.to_json())

# convert the object into a dict
compliance_check_response_dict = compliance_check_response_instance.to_dict()
# create an instance of ComplianceCheckResponse from a dict
compliance_check_response_from_dict = ComplianceCheckResponse.from_dict(compliance_check_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


