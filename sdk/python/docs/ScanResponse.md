# ScanResponse

Scan response (returned when creating a scan)

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**estimated_completion** | **datetime** | Estimated completion time | [optional] 
**queued_at** | **datetime** | When the scan was queued | 
**scan_id** | **str** | Unique scan ID | 
**status** | [**ScanStatus**](ScanStatus.md) | Current scan status | 
**target** | **str** | Target being scanned | 
**websocket_url** | **str** | WebSocket URL for real-time progress | [optional] 

## Example

```python
from cipherrun_client.models.scan_response import ScanResponse

# TODO update the JSON string below
json = "{}"
# create an instance of ScanResponse from a JSON string
scan_response_instance = ScanResponse.from_json(json)
# print the JSON string representation of the object
print(ScanResponse.to_json())

# convert the object into a dict
scan_response_dict = scan_response_instance.to_dict()
# create an instance of ScanResponse from a dict
scan_response_from_dict = ScanResponse.from_dict(scan_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


