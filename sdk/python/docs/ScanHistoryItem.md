# ScanHistoryItem

Individual scan history item

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**duration_ms** | **int** | Scan duration in milliseconds | [optional] 
**grade** | **str** | Overall grade | [optional] 
**scan_id** | **int** | Scan ID | 
**score** | **int** | Overall score | [optional] 
**timestamp** | **datetime** | Scan timestamp | 

## Example

```python
from cipherrun_client.models.scan_history_item import ScanHistoryItem

# TODO update the JSON string below
json = "{}"
# create an instance of ScanHistoryItem from a JSON string
scan_history_item_instance = ScanHistoryItem.from_json(json)
# print the JSON string representation of the object
print(ScanHistoryItem.to_json())

# convert the object into a dict
scan_history_item_dict = scan_history_item_instance.to_dict()
# create an instance of ScanHistoryItem from a dict
scan_history_item_from_dict = ScanHistoryItem.from_dict(scan_history_item_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


