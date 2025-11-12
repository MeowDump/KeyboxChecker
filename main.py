# Forked from https://github.com/SenyxLois/KeyboxCheckerPython
# Modified by https://github.com/MeowDump as per her needs

import asyncio
import aiohttp
import re
import tarfile
import requests
import json
import tempfile
import time
import os
import sys
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec

async def load_from_url():
    url = "https://android.googleapis.com/attestation/status"
    timestamp = int(time.time())
    headers = {
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Expires": "0"
    }
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params={"ts": timestamp}) as resp:
            if resp.status != 200:
                raise Exception(f"Error fetching data: {resp.status}")
            return await resp.json()


def parse_number_of_certificates(xml_file):
    root = ET.parse(xml_file).getroot()
    n = root.find('.//NumberOfCertificates')
    if n is not None:
        return int(n.text.strip())
    raise Exception('No NumberOfCertificates found.')


def parse_certificates(xml_file, count):
    root = ET.parse(xml_file).getroot()
    certs = root.findall('.//Certificate[@format="pem"]')
    if not certs:
        raise Exception("No Certificate found.")
    return [c.text.strip() for c in certs[:count]]


def load_public_key_from_file(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def compare_keys(pk1, pk2):
    return pk1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) == pk2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


async def keybox_check(path):
    # explicit file handling
    if not os.path.exists(path):
        return {"error": f"File not found: {path}"}
    if os.path.isdir(path):
        return {"error": f"Expected a file, not a directory: {path}"}

    # The banner string is correctly defined here
    output = {"banner": "░▀█▀░█▀█░▀█▀░█▀▀░█▀▀░█▀█░▀█▀░▀█▀░█░█░░\n"
                        "░░█░░█░█░░█░░█▀▀░█░█░█▀▄░░█░░░█░░░█░░░\n"
                        "░▀▀▀░▀░▀░░▀░░▀▀▀░▀▀▀░▀░▀░▀▀▀░░▀░░░▀░░░"}

    try:
        pem_count = parse_number_of_certificates(path)
        pem_certs = parse_certificates(path, pem_count)
    except Exception as e:
        output["error"] = str(e)
        return output

    try:
        cert = x509.load_pem_x509_certificate(pem_certs[0].encode(), default_backend())
    except Exception as e:
        output["error"] = str(e)
        return output

    serial = cert.serial_number
    serial_str = hex(serial)[2:].lower()
    subject = cert.subject
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    valid = not_before <= now <= not_after

    validity = "Valid" if valid else "Expired"
    validity_range = f"{not_after.strftime('%Y-%m-%d')}"

    keychain_ok = True
    for i in range(pem_count - 1):
        c1 = x509.load_pem_x509_certificate(pem_certs[i].encode(), default_backend())
        c2 = x509.load_pem_x509_certificate(pem_certs[i + 1].encode(), default_backend())
        if c1.issuer != c2.subject:
            keychain_ok = False
            break
        try:
            sig_alg = c1.signature_algorithm_oid._name
            pk = c2.public_key()
            if "RSA" in sig_alg:
                alg = {
                    'sha256WithRSAEncryption': hashes.SHA256(),
                    'sha1WithRSAEncryption': hashes.SHA1(),
                    'sha384WithRSAEncryption': hashes.SHA384(),
                    'sha512WithRSAEncryption': hashes.SHA512()
                }[sig_alg]
                pk.verify(c1.signature, c1.tbs_certificate_bytes, padding.PKCS1v15(), alg)
            elif "ecdsa" in sig_alg:
                alg = {
                    'ecdsa-with-SHA256': hashes.SHA256(),
                    'ecdsa-with-SHA1': hashes.SHA1(),
                    'ecdsa-with-SHA384': hashes.SHA384(),
                    'ecdsa-with-SHA512': hashes.SHA512()
                }[sig_alg]
                pk.verify(c1.signature, c1.tbs_certificate_bytes, ec.ECDSA(alg))
        except Exception:
            keychain_ok = False
            break

    keychain_status = "Valid" if keychain_ok else "Invalid"

    base = os.path.dirname(os.path.abspath(__file__))
    pem_dir = os.path.join(base, 'lib', 'pem')
    refs = {
        "Google HW Attestation": "google.pem",
        "AOSP SW Attestation": "aosp_ec.pem",
        "AOSP SW Attestation (RSA)": "aosp_rsa.pem",
        "Samsung Knox Attestation": "knox.pem"
    }

    root_cert = x509.load_pem_x509_certificate(pem_certs[-1].encode(), default_backend())
    root_key = root_cert.public_key()
    cert_status = "Unknown / Software"
    for label, file in refs.items():
        pk = load_public_key_from_file(os.path.join(pem_dir, file))
        if compare_keys(root_key, pk):
            cert_status = label
            break

    try:
        revoked = await load_from_url()
    except Exception:
        with open("res/json/status.json", 'r', encoding='utf-8') as f:
            revoked = json.load(f)

    status = None
    for i in range(pem_count):
        c = x509.load_pem_x509_certificate(pem_certs[i].encode(), default_backend())
        sid = hex(c.serial_number)[2:].lower()
        if revoked['entries'].get(sid):
            status = revoked['entries'][sid]
            break

    google_status = status['reason'] if status else "null"
    overall = get_overall_status(status, keychain_status, cert_status, google_status)

    info = {}
    for rdn in subject:
        info[rdn.oid._name] = rdn.value

    serial_match = re.search(r"2\.5\.4\.5=([0-9a-fA-F]+)", str(cert.subject))
    serial_num = serial_match.group(1) if serial_match else "Software or Invalid"

    output.update({
        "serial_number": serial_num,
        "certificate_serial": serial_str,
        "title": info.get('title', 'N/A'),
        "organization": info.get('organizationName', 'N/A'),
        "common_name": info.get('commonName', 'N/A'),
        "status": overall,
        "keychain": keychain_status,
        "root_cert": cert_status,
        "validity": validity,
        "validity_range": validity_range,
        "check_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

    return output


def get_overall_status(status, keychain, cert_status, google_status):
    if status is None:
        if keychain == "Valid":
            if cert_status == "Unknown / Software" and google_status == "null":
                return "Valid (Software signed)"
            mapping = {
                "Google HW Attestation": "Valid (Strong)",
                "AOSP SW Attestation": "Valid (AOSP Software EC)",
                "AOSP SW Attestation (RSA)": "Valid (AOSP Software RSA)",
                "Samsung Knox Attestation": "Valid (Knox Attestation)"
            }
            return mapping.get(cert_status, "Invalid Keybox")
        return "Invalid Keybox"
    else:
        reasons = {
            "KEY_COMPROMISE": "Invalid (Key Compromised)",
            "SOFTWARE_FLAW": "Invalid (Software Flaw)",
            "CA_COMPROMISE": "Invalid (CA Compromised)",
            "SUPERSEDED": "Invalid (Suspended)"
        }
        return reasons.get(google_status, "Valid")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Keybox Checker")
    parser.add_argument("keybox_path", nargs='?', help="Path to the keybox.xml file")
    args = parser.parse_args()
    if not args.keybox_path:
        print("Error: please provide a keybox.xml path.")
        sys.exit(1)
        
    result = asyncio.run(keybox_check(args.keybox_path))
    
    # --- START OF FIX: Handle banner output separately ---
    
    # 1. Check if the banner is present
    banner_string = result.get("banner")
    
    # 2. If present, print it directly (this correctly renders the Unicode art)
    if banner_string:
        print(banner_string)
        
    # 3. Remove the banner key from the dictionary before dumping the JSON
    if "banner" in result:
        del result["banner"]
        
    # --- END OF FIX ---
    
    # 4. Print the rest of the result as clean JSON
    print(json.dumps(result, indent=2))
