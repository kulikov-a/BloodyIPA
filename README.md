# bloodyIPA
bloodhound collector for freeIPA

Fork for BH CE OpenGraph json
<img width="2429" height="520" alt="image" src="https://github.com/user-attachments/assets/ffb8593d-1446-4329-890a-9520c51ae569" />


in progress: web api is working. need more objects and some edges rework

use /api/v2/custom-nodes endpoint (via api-explorer) to send nodes icons json to BH

Requirements:
- python_freeipa
- Requests
- urllib3

```
usage: bloodyipa.py [-h] [-u USERNAME] [-k] [-p PASSWORD] [-dc HOST] [-v] [-use_ldap]
                    [-no_verify_certificate]

  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Domain admin username
  -k, --kerberos        Use Kerberos for auth
  -p PASSWORD, --password PASSWORD
                        Domain admin password
  -dc HOST, --domain-controller HOST
                        DC hostname
  -v                    Enable verbose output
  -use_ldap             Collect objects from ldap
  -no_verify_certificate
                        No verify certificate
```
