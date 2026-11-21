# IKEv2 sign-in and server certificates

IKEv2 EAP authenticates a person with their VPN username and password. Separately,
the phone verifies the server's certificate before sending an EAP response. A
server-certificate error is not evidence of a wrong password or a requirement for
a client certificate.

## New single-server installs

Rookstride attempts public certificate setup after installing/enrolling IKEv2.
It uses the entered public IPv4 address or hostname, Certbot 5.9.0 and automatic
HTTP validation. No domain purchase or additional setup question is required for
an IP certificate. The server must be reachable on TCP80 during validation;
Rookstride uses its own firewall chain and closes that temporary rule afterward.
An existing web service is never stopped. Busy/blocked validation, unsupported
identifiers or unavailable dependencies retain secure pinned-profile access.

Public mode lets a standard strongSwan client use IKEv2 EAP (Username/Password),
the matching server address and automatic CA selection. A newly created account
has **Share sign-in details**, containing readable server/username/password text.
A profile file is also available. A private-CA deployment instead shares a
`.sswan` profile containing the trusted server certificate. Existing account
lists do not return saved passwords; readable details require the password still
known from that account's creation.

Public profiles omit `remote.cert`; they use normal trusted-CA and identity
validation. A private profile continues to include its certificate. Rookstride
supports both formats. It does not disable verification or accept arbitrary
certificates. Client certificates/PKCS#12 files are not used for these EAP users.

## Renewal and reinstalling

IP certificates use Let's Encrypt's short-lived profile. A systemd timer checks
renewal every four hours with a small randomized delay. Only the owned lineage is
renewed. The helper verifies the chain, every requested name, key match and expiry
before atomically copying credentials and reloading strongSwan. Failed reloads
restore the preceding identity. Public mode has an installation ID independent
of the leaf certificate, so ordinary renewal does not invalidate phone profiles
or favorite shortcuts.

Rookstride can migrate a managed cached profile in place when an authenticated SSH
report links the public setup to its exact previous private-certificate instance.
The saved VPN login/password and favorite remain. An independently imported pinned
profile needs one update when its server is explicitly migrated to public mode. Ordinary management enrollment
does not silently perform that migration. An operator with the current helper may
use `sudo python3 /opt/rookstride/server/ike_public.py enable`; known additional
hostnames can be added with `--alias vpn.your-domain.tld`. Public validation must
succeed for every name. Hostname support is not implied by DNS pointing at an IP:
the certificate must also cover the hostname.

Once using public trust, clients can keep their sign-in details across a rebuild
if the same address/certificate names are restored and the administrator recreates
the same VPN username/password. The rebuilt server must obtain a valid public
certificate. This does not remove the rebuild's downtime or recreate accounts.
Choose the hostname as the setup address for hostname-based access. The app also
remembers hostnames read from a verified managed server and passes them when
reinstalling IKEv2 from that saved server. Removing that server from the phone
removes its saved metadata; external resets cannot communicate unknown names.

Managed VPN removal stops certificate renewal and removes the owned certificate,
issuer files, ACME state and virtual environment with the other VPN data. Ubuntu,
SSH and unrelated services remain. A whole operating-system rebuild is a separate
provider operation; changed SSH host keys still need a legitimate identity review.

## Implementation and limits

- Certificate code: `server/ike_public.py`; recipe integration: `server/deploy.py`.
- Configuration/ACME state: `/etc/single-vps-vpn/`.
- Private client environment: `/opt/rookstride/ike-acme-venv/`.
- Renewal units: `rookstride-ike-cert-renew.service` and `.timer`.
- Expiry/trust/names: the existing read-only server status over pinned SSH.
- Certbot/ACME versions are pinned and included in internal upstream review.
- This automatic conversion targets fresh single-server IKEv2. Double VPN and
  other protocols retain their existing certificate/key arrangements.
- CA issuance, reachability, supported Android roots and actual VPN traffic are
  separate checks. Certificate setup does not bypass blocked UDP500/4500.

References: [strongSwan profile format](https://docs.strongswan.org/docs/latest/os/androidVpnClientProfiles.html),
[Let's Encrypt IP certificate setup](https://letsencrypt.org/2026/03/11/shorter-certs-certbot),
[Certbot releases](https://github.com/certbot/certbot/releases/tag/v5.9.0).
