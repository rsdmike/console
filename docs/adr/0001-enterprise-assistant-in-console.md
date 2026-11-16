# 1. Rebuild Enterprise Assistant in Go, inside Console

Date: 2026-11-16

## Status

Proposed (spike in progress)

## Context

Enterprise Assistant (EA) is the bridge between Intel AMT provisioning and a Microsoft enterprise.
For 802.1x (EAP-TLS, PEAPv0/EAP-MSCHAPv2) and for AMT TLS certificates issued by a Microsoft CA,
it does the following:

- it creates or resets an `iME-<name>` computer object in Active Directory, sets its password, adds
  it to security groups, and removes it later;
- it builds an unsigned ("null-signed") PKCS#10 for a key pair that AMT generated. AMT signs it,
  EA submits it to the CA and returns the certificate. It revokes the old certificate when it is
  replaced.

Today EA is a .NET Framework 4.8 WinForms app and Windows service. It must run on a domain-joined
Windows Server. It talks to the CA through COM interop DLLs (`certcli.dll` `ICertRequest`,
`certadm.dll` `ICertAdmin`, `certenroll.dll`) and to AD through ADSI (`System.DirectoryServices`).
Two clients use it: RPS over a WebSocket "satellite" protocol, and rpc-go over HTTP
(`/api/authenticate/{guid}`, `/api/configure/{profile,keypair,csr}/{guid}`).

Console is the Go v3 successor to MPS and RPS, and it already runs as server infrastructure. It
already exports profiles that point rpc-go at an EA URL (`ea.url`, `ea.username`, `ea.password`).

Moving to .NET 8+ would modernize the code but not the platform: the CA COM objects exist only on
Windows, and .NET ships no managed MS-ICPR or MS-CSRA client. Every Windows dependency maps to a
documented wire protocol that has a pure-Go client:

| Need | Protocol | Go library |
|---|---|---|
| AD computer objects, groups, CA and template discovery | LDAP over TLS (636) | `go-ldap/ldap/v3` |
| Submit a CSR to the CA | MS-ICPR `CertServerRequest` (RPC, sealed) | `oiweiwei/go-msrpc` `msrpc/icpr` |
| Revoke a certificate | MS-CSRA `ICertAdminD::RevokeCertificate` (DCOM) | `oiweiwei/go-msrpc` `msrpc/dcom/csra` |
| Null-signed PKCS#10 with SANs and template extension | ASN.1 | Go standard library |

## Decision

We will rebuild EA in Go as a feature of Console, not as a separate service:

1. Console serves the existing rpc-go EA contract under `/ea` (so `--eaAddress https://<console>/ea`),
   with the same request and response shapes. rpc-go does not change.
2. Libraries live in `pkg/ea/{csr,ad,adcs}` with no internal dependencies, so a standalone EA
   binary can reuse them if a customer needs EA on a different host.
3. Console reaches AD with an LDAPS simple bind as a dedicated service account. LDAPS satisfies
   the Windows Server 2025 LDAP signing default and the encrypted connection that `unicodePwd`
   requires. The CA is reached over MS-RPC with sealing, authenticated as the same account.
4. Settings (AD, CA, template, naming) are edited in sample-web-ui on an Enterprise Assistant
   settings page, through a new `/api/v2/admin/enterprise-assistant` surface.
5. The RPS WebSocket satellite mode and the WinForms UI are not ported. RPS (v2) deployments keep
   the existing EA.

## Consequences

- EA runs on Linux, Windows and macOS, in containers, with no domain join. One less Windows Server
  to operate.
- A service account (password today, keytab or gMSA later) replaces the implicit machine identity.
  It needs: create and delete computer objects on the target OU, Enroll on the template, and
  "Issue and Manage Certificates" on the CA for revoke.
- The domain controller needs an LDAPS certificate (normal wherever AD CS is deployed).
- We depend on go-msrpc (MIT, mostly one maintainer). Mitigation: keep the CA client behind an
  interface. A Windows-only COM backend (go-ole on certcli) can be added if the library stalls.
- The null-signed CSR must be one AMT accepts. The spike proves it on real AMT hardware.
- Spike debt to settle before production: settings and the bind password live in `config.yml` in
  plain text, like `ea.password` today (move to Vault or the encrypted DB); the EA token key lives
  in memory per process (multi-replica deployments need a shared key); Kerberos is not wired yet
  (NTLM is used for RPC and simple bind for LDAP); Fuego/OpenAPI and Postman entries are missing.
