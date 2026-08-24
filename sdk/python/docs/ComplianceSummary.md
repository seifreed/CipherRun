# ComplianceSummary

Compliance summary

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**compliance_percentage** | **float** | Compliance percentage | 
**failed** | **int** | Failed requirements | 
**passed** | **int** | Passed requirements | 
**total** | **int** | Total requirements | 
**warnings** | **int** | Warnings | 

## Example

```python
from cipherrun_client.models.compliance_summary import ComplianceSummary

# TODO update the JSON string below
json = "{}"
# create an instance of ComplianceSummary from a JSON string
compliance_summary_instance = ComplianceSummary.from_json(json)
# print the JSON string representation of the object
print(ComplianceSummary.to_json())

# convert the object into a dict
compliance_summary_dict = compliance_summary_instance.to_dict()
# create an instance of ComplianceSummary from a dict
compliance_summary_from_dict = ComplianceSummary.from_dict(compliance_summary_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


