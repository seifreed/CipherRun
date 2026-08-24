# StatsResponse

Statistics response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**api_usage** | [**ApiUsageStats**](ApiUsageStats.md) | Current API usage statistics | 
**avg_scan_duration_seconds** | **float** | Average scan duration in seconds | 
**completed_scans** | **int** | Completed scans | 
**failed_scans** | **int** | Failed scans | 
**scans_last_24h** | **int** | Scans in last 24 hours | 
**scans_last_7d** | **int** | Scans in last 7 days | 
**top_domains** | [**List[DomainStats]**](DomainStats.md) | Most scanned domains (top 10) | 
**total_scans** | **int** | Total scans performed | 

## Example

```python
from cipherrun_client.models.stats_response import StatsResponse

# TODO update the JSON string below
json = "{}"
# create an instance of StatsResponse from a JSON string
stats_response_instance = StatsResponse.from_json(json)
# print the JSON string representation of the object
print(StatsResponse.to_json())

# convert the object into a dict
stats_response_dict = stats_response_instance.to_dict()
# create an instance of StatsResponse from a dict
stats_response_from_dict = StatsResponse.from_dict(stats_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


