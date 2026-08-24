# ScanStatusResponse

Scan status response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**completed_at** | **datetime** | When scan completed | [optional] 
**current_stage** | **str** | Current stage being executed | [optional] 
**error** | **str** | Error message if failed | [optional] 
**eta_seconds** | **int** | Estimated seconds until completion | [optional] 
**progress** | **int** | Progress percentage (0-100) | 
**results_url** | **str** | Link to results (if completed) | [optional] 
**scan_id** | **str** | Unique scan ID | 
**started_at** | **datetime** | When scan started | [optional] 
**status** | [**ScanStatus**](ScanStatus.md) | Current status | 

## Example

```python
from cipherrun_client.models.scan_status_response import ScanStatusResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ScanStatusResponse from a JSON string
scan_status_response_instance = ScanStatusResponse.from_json(json)
# print the JSON string representation of the object
print(ScanStatusResponse.to_json())

# convert the object into a dict
scan_status_response_dict = scan_status_response_instance.to_dict()
# create an instance of ScanStatusResponse from a dict
scan_status_response_from_dict = ScanStatusResponse.from_dict(scan_status_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


