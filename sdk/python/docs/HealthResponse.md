# HealthResponse

Health check response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**active_scans** | **int** | Current number of active scans | [optional] 
**database** | **str** | Database connection status | [optional] 
**queue** | **str** | Job queue health status | [optional] 
**queued_scans** | **int** | Queued scans | [optional] 
**status** | **str** | Service status | 
**uptime_seconds** | **int** | Uptime in seconds | 
**version** | **str** | Service version | 

## Example

```python
from cipherrun_client.models.health_response import HealthResponse

# TODO update the JSON string below
json = "{}"
# create an instance of HealthResponse from a JSON string
health_response_instance = HealthResponse.from_json(json)
# print the JSON string representation of the object
print(HealthResponse.to_json())

# convert the object into a dict
health_response_dict = health_response_instance.to_dict()
# create an instance of HealthResponse from a dict
health_response_from_dict = HealthResponse.from_dict(health_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


