#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tls_scan.py
Probe which TLS versions and cipher names a host or IP accepts.
Works on Python 3.6+. If target is an IP address, SNI is skipped.
"""

import ssl
import socket
import sys
import argparse
import ipaddress

# Compatibility: some older Python versions may not have ssl.TLSVersion
try:
    TLS = {
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
except AttributeError:
    TLS = {
        "TLSv1": None,
        "TLSv1.1": None,
        "TLSv1.2": None,
        "TLSv1.3": None,
    }

def is_ip_address(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def get_supported_tls_versions(hostname_or_ip, port=443, use_sni=True):
    supported_versions = {}
    for name, version in TLS.items():
        if version is None:
            supported_versions[name] = None
            continue

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = version
        context.maximum_version = version
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        server_hostname = hostname_or_ip if use_sni else None

        try:
            with socket.create_connection((hostname_or_ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                    cipher = ssock.cipher()
                    supported_versions[name] = cipher
        except ssl.SSLError:
            supported_versions[name] = None
        except Exception:
            supported_versions[name] = None

    return supported_versions

def get_supported_ciphers(hostname_or_ip, port=443, tls_version=None, use_sni=True):
    base_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if tls_version is not None:
        base_ctx.minimum_version = tls_version
        base_ctx.maximum_version = tls_version
    base_ctx.check_hostname = False
    base_ctx.verify_mode = ssl.CERT_NONE

    supported_ciphers = []
    for cipher in base_ctx.get_ciphers():
        name = cipher.get("name")
        try:
            cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if tls_version is not None:
                cctx.minimum_version = tls_version
                cctx.maximum_version = tls_version
            cctx.check_hostname = False
            cctx.verify_mode = ssl.CERT_NONE
            cctx.set_ciphers(name)
        except Exception:
            continue

        server_hostname = hostname_or_ip if use_sni else None

        try:
            with socket.create_connection((hostname_or_ip, port), timeout=5) as sock:
                with cctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                    supported_ciphers.append(name)
        except Exception:
            continue

    return supported_ciphers

def main():
    if sys.version_info < (3, 6):
        print("Please run this script with Python 3.6+.")
        return

    parser = argparse.ArgumentParser(description="Scan TLS versions and ciphers for a host or IP")
    parser.add_argument("target", nargs="?", help="Hostname or IP address to scan (e.g. example.com or 1.2.3.4)")
    parser.add_argument("--port", type=int, default=443, help="TCP port to connect to (default: 443)")
    args = parser.parse_args()

    if args.target:
        target = args.target.strip()
    else:
        target = input("Enter the hostname or IP (e.g. example.com or 1.2.3.4): ").strip()

    if not target:
        print("No target provided, exiting.")
        return

    use_sni = not is_ip_address(target)
    if use_sni:
        print("Target appears to be a hostname; using SNI (server_hostname={}).".format(target))
    else:
        print("Target appears to be an IP address; skipping SNI (server_hostname=None).")

    print("\nTesting TLS versions for {}:{}...\n".format(target, args.port))
    results = get_supported_tls_versions(target, port=args.port, use_sni=use_sni)

    for version, cipher in results.items():
        if cipher:
            print("{}: Supported - cipher: {}".format(version, cipher))
        else:
            print("{}: Not supported".format(version))

    tls12 = TLS.get("TLSv1.2")
    if tls12 is not None:
        print("\nScanning ciphers for TLS 1.2 on {}:{}...\n".format(target, args.port))
        ciphers = get_supported_ciphers(target, port=args.port, tls_version=tls12, use_sni=use_sni)
        print("TLS 1.2 supported ciphers ({}):".format(len(ciphers)))
        for c in ciphers:
            print("  {}".format(c))
    else:
        print("\nSkipping TLS 1.2 cipher scan because this Python/ssl build lacks TLSVersion enums.")

if __name__ == "__main__":
    main()
