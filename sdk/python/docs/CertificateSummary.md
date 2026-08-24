# CertificateSummary

Certificate summary

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**common_name** | **str** | Subject common name | 
**days_until_expiry** | **int** | Days until expiry | 
**fingerprint** | **str** | SHA-256 fingerprint | 
**hostnames** | **List[str]** | Associated hostnames | 
**is_expired** | **bool** | Certificate is expired | 
**is_expiring_soon** | **bool** | Certificate is expiring soon (&lt; 30 days) | 
**issuer** | **str** | Issuer | 
**san** | **List[str]** | Subject alternative names | 
**valid_from** | **datetime** | Valid from | 
**valid_until** | **datetime** | Valid until | 

## Example

```python
from cipherrun_client.models.certificate_summary import CertificateSummary

# TODO update the JSON string below
json = "{}"
# create an instance of CertificateSummary from a JSON string
certificate_summary_instance = CertificateSummary.from_json(json)
# print the JSON string representation of the object
print(CertificateSummary.to_json())

# convert the object into a dict
certificate_summary_dict = certificate_summary_instance.to_dict()
# create an instance of CertificateSummary from a dict
certificate_summary_from_dict = CertificateSummary.from_dict(certificate_summary_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


