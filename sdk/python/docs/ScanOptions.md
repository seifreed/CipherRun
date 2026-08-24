# ScanOptions

Scan options

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**analyze_certificates** | **bool** | Analyze certificates | [optional] [default to False]
**client_simulation** | **bool** | Run client simulations | [optional] [default to False]
**full_scan** | **bool** | Run full comprehensive scan | [optional] [default to False]
**ip** | **str** | Specific IP address to test | [optional] 
**ipv4_only** | **bool** | Use IPv4 only | [optional] [default to False]
**ipv6_only** | **bool** | Use IPv6 only | [optional] [default to False]
**starttls_protocol** | **str** | STARTTLS protocol (smtp, imap, pop3, etc.) | [optional] 
**test_ciphers** | **bool** | Test all cipher suites | [optional] [default to False]
**test_http_headers** | **bool** | Test HTTP security headers | [optional] [default to False]
**test_protocols** | **bool** | Test all protocols (SSLv2, SSLv3, TLS 1.0-1.3) | [optional] [default to False]
**test_vulnerabilities** | **bool** | Test all vulnerabilities | [optional] [default to False]
**timeout_seconds** | **int** | Connection and socket timeout in seconds | [optional] [default to 30]

## Example

```python
from cipherrun_client.models.scan_options import ScanOptions

# TODO update the JSON string below
json = "{}"
# create an instance of ScanOptions from a JSON string
scan_options_instance = ScanOptions.from_json(json)
# print the JSON string representation of the object
print(ScanOptions.to_json())

# convert the object into a dict
scan_options_dict = scan_options_instance.to_dict()
# create an instance of ScanOptions from a dict
scan_options_from_dict = ScanOptions.from_dict(scan_options_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


