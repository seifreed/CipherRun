# ScanHistoryResponse

Scan history response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**domain** | **str** | Domain | 
**port** | **int** | Port | 
**scans** | [**List[ScanHistoryItem]**](ScanHistoryItem.md) | Historical scan records | 
**total_scans** | **int** | Total scans in history | 

## Example

```python
from cipherrun_client.models.scan_history_response import ScanHistoryResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ScanHistoryResponse from a JSON string
scan_history_response_instance = ScanHistoryResponse.from_json(json)
# print the JSON string representation of the object
print(ScanHistoryResponse.to_json())

# convert the object into a dict
scan_history_response_dict = scan_history_response_instance.to_dict()
# create an instance of ScanHistoryResponse from a dict
scan_history_response_from_dict = ScanHistoryResponse.from_dict(scan_history_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


