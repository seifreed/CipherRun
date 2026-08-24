# DomainStats

Domain statistics

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**domain** | **str** | Domain name | 
**last_scan** | **datetime** | Last scan time | 
**scan_count** | **int** | Number of scans | 

## Example

```python
from cipherrun_client.models.domain_stats import DomainStats

# TODO update the JSON string below
json = "{}"
# create an instance of DomainStats from a JSON string
domain_stats_instance = DomainStats.from_json(json)
# print the JSON string representation of the object
print(DomainStats.to_json())

# convert the object into a dict
domain_stats_dict = domain_stats_instance.to_dict()
# create an instance of DomainStats from a dict
domain_stats_from_dict = DomainStats.from_dict(domain_stats_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


