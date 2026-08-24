# ScanRequest

Scan request payload

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**options** | [**ScanOptions**](ScanOptions.md) | Optional scan options | [optional] 
**target** | **str** | Target to scan (hostname:port or just hostname) | 
**webhook_url** | **str** | Optional webhook URL to call when scan completes | [optional] 

## Example

```python
from cipherrun_client.models.scan_request import ScanRequest

# TODO update the JSON string below
json = "{}"
# create an instance of ScanRequest from a JSON string
scan_request_instance = ScanRequest.from_json(json)
# print the JSON string representation of the object
print(ScanRequest.to_json())

# convert the object into a dict
scan_request_dict = scan_request_instance.to_dict()
# create an instance of ScanRequest from a dict
scan_request_from_dict = ScanRequest.from_dict(scan_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


