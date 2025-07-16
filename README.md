# Shadow Credentials Attack Tool

A Python3 implementation for adding Key Credentials to Active Directory machine accounts, enabling PKINIT authentication. This tool follows Microsoft's exact binary format requirements for the `msDS-KeyCredentialLink` attribute.

## Key Features

- Implements Microsoft's proprietary KeyCredential binary structure
- Supports both NTLM and Kerberos authentication
- Generates compliant RSA key pairs and certificates
- Preserves existing credentials when adding new ones
- Includes proper Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2)
- Enforces LDAPS with certificate validation
- Secure memory cleanup of sensitive data

## Prerequisites

- Python 3.6+
- Kali Linux 2025 (or compatible environment)
- Required packages:
  ```bash
  pip install ldap3 cryptography
Installation
bash
git clone https://github.com/your-repo/shadow-creds.git
cd shadow-creds
Usage
Basic Usage with Username/Password
bash
python3 shadow_creds.py -d dc01.corp.local -u attacker -p Password123 -t target-machine [-o output_file]
Using Kerberos Authentication
bash
export KRB5CCNAME=/path/to/ticket.ccache
python3 shadow_creds.py -d dc01.corp.local -k -t target-machine [-o output_file]
Removing Credentials
bash
python3 shadow_creds.py -d dc01.corp.local -k -t target-machine --remove
Arguments
Argument	Description
-d, --domain	Domain controller hostname (e.g., dc01.corp.local)
-u, --username	Username for NTLM authentication
-p, --password	Password for NTLM authentication
-k, --kerberos	Use Kerberos authentication from ccache
-t, --target	Target machine name (without $ suffix)
-o, --output	Base filename for key material output
-r, --remove	Remove shadow credentials instead of adding
-v, --verbose	Enable verbose output
Technical Implementation
The tool implements Microsoft's exact binary structure for KeyCredentials:

Binary Structure:

text
Version (4 bytes)
Flags (4 bytes) 
KeyId (16 bytes GUID)
CreationTime (8 bytes FILETIME)
KeyUsage (4 bytes)
KeyProvider (4 bytes)
DeviceId (16 bytes GUID)
KeyMaterialLength (4 bytes)
KeyMaterial (DER certificate)
CustomDataLength (4 bytes)
CustomData (variable)
Certificate Requirements:

Includes Smart Card Logon EKU

Valid Key Usage for authentication

Proper subject/issuer naming

2048-bit RSA keys

Security Features:

Enforces LDAPS with TLS 1.2

Validates server certificates

Securely wipes sensitive memory

Preserves existing credentials

Operational Security Considerations
Monitor for unexpected modifications to msDS-KeyCredentialLink

Restrict write permissions on machine accounts

Enable "PKINIT Freshness" protection (Windows Server 2019+)

Review certificate authentication events

References
Microsoft KeyCredential Structure

Shadow Credentials Attack

Legal Disclaimer
This tool is provided for authorized security testing and educational purposes only. Unauthorized use against systems without explicit permission is illegal.
