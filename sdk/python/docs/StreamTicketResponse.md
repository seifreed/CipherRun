# StreamTicketResponse


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**expires_at** | **datetime** |  | 
**ticket** | **str** |  | 
**websocket_url** | **str** |  | 

## Example

```python
from cipherrun_client.models.stream_ticket_response import StreamTicketResponse

# TODO update the JSON string below
json = "{}"
# create an instance of StreamTicketResponse from a JSON string
stream_ticket_response_instance = StreamTicketResponse.from_json(json)
# print the JSON string representation of the object
print(StreamTicketResponse.to_json())

# convert the object into a dict
stream_ticket_response_dict = stream_ticket_response_instance.to_dict()
# create an instance of StreamTicketResponse from a dict
stream_ticket_response_from_dict = StreamTicketResponse.from_dict(stream_ticket_response_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


