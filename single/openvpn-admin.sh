#!/bin/bash
set -euo pipefail
export EASYRSA_BATCH=1 EASYRSA_PKI=/vpn/pki EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1
umask 077
case "${1:-}" in
  init)
    [[ ! -e /vpn/pki ]] || exit 1
    /usr/share/easy-rsa/easyrsa init-pki
    EASYRSA_REQ_CN=Rookstride /usr/share/easy-rsa/easyrsa build-ca nopass
    /usr/share/easy-rsa/easyrsa build-server-full server nopass
    /usr/share/easy-rsa/easyrsa gen-crl
    openvpn --genkey secret /vpn/tls-crypt.key
    ;;
  add) [[ ${2:-} =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$ ]] || exit 1; /usr/share/easy-rsa/easyrsa build-client-full "$2" nopass ;;
  revoke) [[ ${2:-} =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$ ]] || exit 1; /usr/share/easy-rsa/easyrsa revoke "$2"; /usr/share/easy-rsa/easyrsa gen-crl ;;
  *) exit 1 ;;
esac
