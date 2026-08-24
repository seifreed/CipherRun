# ApiUsageStats

API usage statistics

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**avg_response_time_ms** | **float** | Average response time in milliseconds | 
**requests_last_day** | **int** | Requests in last day | 
**requests_last_hour** | **int** | Requests in last hour | 

## Example

```python
from cipherrun_client.models.api_usage_stats import ApiUsageStats

# TODO update the JSON string below
json = "{}"
# create an instance of ApiUsageStats from a JSON string
api_usage_stats_instance = ApiUsageStats.from_json(json)
# print the JSON string representation of the object
print(ApiUsageStats.to_json())

# convert the object into a dict
api_usage_stats_dict = api_usage_stats_instance.to_dict()
# create an instance of ApiUsageStats from a dict
api_usage_stats_from_dict = ApiUsageStats.from_dict(api_usage_stats_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


