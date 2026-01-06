This section serves as a quick reference for Certipy's commands, summarizing their purpose and usage. Use this as a cheat-sheet when operating Certipy during assessments or audits. Each command is invoked as a sub-command to `certipy`. Common global options like `-u/-p` (credentials), `-hashes`, `-dc-ip`, and `-debug` are omitted for brevity.

## Summary of Commands

### `account`

**Manage AD user/computer accounts**
Usage: `certipy account [create|read|update|delete] -user <SAMName> [options]`

Key Flags:

* `-group <CN=Group,...>` - Group to add the account to
* `-dns <hostname>` - Set dNSHostName
* `-upn <user@domain>` - Set UserPrincipalName
* `-sam <NewSAM>` - Set new SAM name
* `-spns <SPN1,SPN2,...>` - Set SPNs
* `-pass <password>` - Set password

---

### `auth`

**Authenticate using a certificate**
Usage: `certipy auth -pfx <cert.pfx> [options]`

Key Flags:

* `-password <pfx_password>` - PFX password
* `-print` - Print TGT in kirbi format
* `-kirbi` - Save as .kirbi
* `-ldap-shell` - Start LDAP shell after auth

---

### `ca`

**Manage CA templates and requests**
Usage: `certipy ca -ca <CAName> [options]`

Key Flags:

* `-list-templates` - List enabled templates
* `-enable-template <Template>` / `-disable-template` - Manage issuance
* `-issue-request <ID>` / `-deny-request <ID>` - Manage requests
* `-add-officer <User>` / `-remove-officer` - Manage CA managers

---

### `cert`

**Import/export/manipulate local certs**
Usage: `certipy cert [options]`

Key Flags:

* `-pfx/-key/-cert` - Input from file(s)
* `-export` - Export to new PFX
* `-out <filename>` - Output file
* `-nocert/-nokey` - Export only one component
* `-export-password` - Set output PFX password

---

### `find`

**Enumerate AD CS config & vulnerabilities**
Usage: `certipy find [options]`

Key Flags:

* `-text/-json/-csv/-stdout` - Output format
* `-output <prefix>` - Save to files
* `-enabled` - Show only enabled templates
* `-vulnerable` - Show only vulnerable templates
* `-oids` - Show Issuance Policies
* `-hide-admins` - Suppress admin entries

---

### `parse`

**Analyze AD CS registry exports offline**
Usage: `certipy parse <file> [options]`

Key Flags:

* `-format <bof|reg>` - Input file format
* `-domain/-ca` - Set context info
* `-enabled` / `-vulnerable` - Filter results
* `-sids` / `-published templates` - Customize analysis
* `-output <prefix>` - Output file prefix

---

### `forge`

**Create forged or golden certificates**
Usage: `certipy forge [options]`

Key Flags:

* `-ca-pfx <file>` - CA cert/key for signing
* `-subject <DN>` / `-upn` / `-dns` / `-sid` - Certificate subject info
* `-template <file>` - Clone another cert
* `-key-size <bits>` / `-validity-period <days>` - Key/cert config
* `-out <file>` - Output forged PFX

---

### `relay`

**Perform NTLM relay to AD CS**
Usage: `certipy relay -target <proto://host> [options]`

Key Flags:

* `-ca <CAName>` / `-template <Template>` - Certificate request details
* `-out <file>` - Save cert/key
* `-interface <IP>` / `-port <Port>` - Relay server bind settings
* `-forever` - Keep server alive
* `-enum-templates` - Enumerate via relay
* `-retrieve <RequestID>` - Fetch existing request result

---

### `req`

**Request certificates from AD CS**
Usage: `certipy req -ca <CAName> -template <Template> [options]`

Key Flags:

* `-subject <DN>` / `-upn` / `-dns` / `-sid` - Request subject
* `-on-behalf-of <DOMAIN\User>` - Request as another user
* `-pfx/-pfx-password` - Auth or sign with existing PFX
* `-renew` - Renew an existing cert
* `-archive-key` / `-cax-cert` - Key archival options
* `-web` / `-dcom` / `-dynamic-endpoint` - Request method

---

### `shadow`

**Abuse Key Credential Links / Shadow Credentials**
Usage: `certipy shadow <list|add|remove|clear|info|auto> [options]`

Key Flags:

* `-account <target>` - Target account
* `-device-id <GUID>` - Specific Device ID
* `-out <file>` - Save certificate/key

---

### `template`

**View or modify certificate template config**
Usage: `certipy template -template <Name> [options]`

Key Flags:

* `-save-configuration <file>` - Save current config
* `-write-configuration <file>` - Apply config from file
* `-write-default-configuration` - Apply ESC1-vulnerable default
* `-no-save` - Skip backup
* `-force` - Suppress confirmation prompts

---

## Full Command Reference

### Global Options

```text
$ certipy -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy [-v] [-h] [-debug] {account,auth,ca,cert,find,parse,forge,relay,req,shadow,template} ...

Active Directory Certificate Services enumeration and abuse

positional arguments:
  {account,auth,ca,cert,find,parse,forge,relay,req,shadow,template}
                        Action
    account             Manage user and machine accounts
    auth                Authenticate using certificates
    ca                  Manage CA and certificates
    cert                Manage certificates and private keys
    find                Enumerate AD CS
    parse               Offline enumerate AD CS based on registry data
    forge               Create Golden Certificates or self-signed certificates
    relay               NTLM Relay to AD CS HTTP Endpoints
    req                 Request certificates
    shadow              Abuse Shadow Credentials for account takeover
    template            Manage certificate templates

options:
  -v, --version         Show Certipy's version number and exit
  -h, --help            Show this help message and exit
  -debug, --debug       Enable debug output
```

---

### `account -h`

```text
$ certipy account -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy account [-h] -user SAM Account Name [-group CN=Computers,DC=test,DC=local] [-dns hostname] [-upn principal name] [-sam account name] [-spns service names] [-pass password]
                       [-dc-ip ip address] [-dc-host hostname] [-target-ip ip address] [-target dns/ip address] [-ns ip address] [-dns-tcp] [-timeout seconds] [-u username@domain]
                       [-p password] [-hashes [lmhash:]nthash] [-k] [-aes hex key] [-no-pass] [-ldap-scheme ldap scheme] [-ldap-port port] [-no-ldap-channel-binding] [-no-ldap-signing]
                       [-ldap-simple-auth] [-ldap-user-dn dn]
                       {create,read,update,delete}

Create, read, update, and delete Active Directory user and computer accounts. This command allows manipulating account properties including DNS names, service principal names (SPNs), and
passwords.

positional arguments:
  {create,read,update,delete}
                        Action to perform: create (new account), read (view account properties), update (modify existing account), delete (remove account)

options:
  -h, --help            show this help message and exit

target options:
  -user SAM Account Name
                        Logon name for the account to target
  -group CN=Computers,DC=test,DC=local
                        Group to which the account will be added. If omitted, CN=Computers,<default path> will be used

attribute options:
  -dns hostname         Set the DNS hostname for the account (e.g., computer.domain.local)
  -upn principal name   Set the User Principal Name for the account (e.g., user@domain.local)
  -sam account name     Set the SAM Account Name for the account (e.g., computer$ or username)
  -spns service names   Set the Service Principal Names for the account (comma-separated)
  -pass password        Set the password for the account

connection options:
  -dc-ip ip address     IP address of the domain controller. If omitted, it will use the domain part (FQDN) specified in the target parameter
  -dc-host hostname     Hostname of the domain controller. Required for Kerberos authentication during certain operations. If omitted, the domain part (FQDN) specified in the account
                        parameter will be used
  -target-ip ip address
                        IP address of the target machine. If omitted, it will use whatever was specified as target. Useful when target is the NetBIOS name and cannot be resolved
  -target dns/ip address
                        DNS name or IP address of the target machine. Required for Kerberos authentication
  -ns ip address        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections in seconds (default: 10)

authentication options:
  -u username@domain, -username username@domain
                        Username to authenticate with
  -p password, -password password
                        Password for authentication
  -hashes [lmhash:]nthash
                        NTLM hash
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
  -no-pass              Don't ask for password (useful for -k)

ldap options:
  -ldap-scheme ldap scheme
                        LDAP connection scheme to use (default: ldaps)
  -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
  -no-ldap-channel-binding
                        Don't use LDAP channel binding for LDAP communication (LDAPS only)
  -no-ldap-signing      Don't use LDAP signing for LDAP communication (LDAP only)
  -ldap-simple-auth     Use SIMPLE LDAP authentication instead of NTLM
  -ldap-user-dn dn      Distinguished Name of target account for LDAP authentication
```

---

### `auth -h`

```text
$ certipy auth -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy auth [-h] -pfx pfx/p12 file name [-password password] [-no-save] [-no-hash] [-print] [-kirbi] [-dc-ip ip address] [-ns nameserver] [-dns-tcp] [-timeout seconds]
                    [-username username] [-domain domain] [-ldap-shell] [-ldap-scheme ldap scheme] [-ldap-port port] [-ldap-user-dn dn]

Authenticate to Active Directory services using certificates. This command enables certificate-based authentication to obtain Kerberos tickets, NT hashes, or establish LDAP connections.

options:
  -h, --help            show this help message and exit

certificate options:
  -pfx pfx/p12 file name
                        Path to certificate and private key (PFX/P12 format)
  -password password    Password for the PFX/P12 file

output options:
  -no-save              Don't save Kerberos TGT to file
  -no-hash              Don't request NT hash from Kerberos
  -print                Print Kerberos TGT in Kirbi format to console
  -kirbi                Save Kerberos TGT in Kirbi format (default is ccache)

connection options:
  -dc-ip ip address     IP Address of the domain controller. If omitted, it will use the domain part (FQDN) specified in the target parameter
  -ns nameserver        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections in seconds

authentication options:
  -username username    Username to authenticate as (extracted from certificate if omitted)
  -domain domain        Domain name to authenticate to (extracted from certificate if omitted)
  -ldap-shell           Authenticate with the certificate via Schannel against LDAP

ldap options:
  -ldap-scheme ldap scheme
                        LDAP connection scheme to use (default: ldaps)
  -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
  -ldap-user-dn dn      Distinguished Name of target account for LDAP authentication
```

---

### `ca -h`

```text
$ certipy cert -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy cert [-h] [-pfx infile] [-password password] [-key infile] [-cert infile] [-export] [-out outfile] [-nocert] [-nokey] [-export-password password]

Import, export, and manipulate certificates and private keys locally. This command supports various operations like converting between formats, extracting components, and creating PFX
files.

options:
  -h, --help            show this help message and exit

input options:
  -pfx infile           Load certificate and private key from PFX/P12 file
  -password password    Password for the input PFX/P12 file
  -key infile           Load private key from PEM or DER file
  -cert infile          Load certificate from PEM or DER file

output options:
  -export               Export to PFX/P12 file (default format)
  -out outfile          Output filename for the exported certificate/key
  -nocert               Don't include certificate in output (key only)
  -nokey                Don't include private key in output (certificate only)
  -export-password password
                        Password to protect the output PFX/P12 file
```

---

### `cert -h`

```text
$ certipy cert -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy cert [-h] [-pfx infile] [-password password] [-key infile] [-cert infile] [-export] [-out outfile] [-nocert] [-nokey] [-export-password password]

Import, export, and manipulate certificates and private keys locally. This command supports various operations like converting between formats, extracting components, and creating PFX
files.

options:
  -h, --help            show this help message and exit

input options:
  -pfx infile           Load certificate and private key from PFX/P12 file
  -password password    Password for the input PFX/P12 file
  -key infile           Load private key from PEM or DER file
  -cert infile          Load certificate from PEM or DER file

output options:
  -export               Export to PFX/P12 file (default format)
  -out outfile          Output filename for the exported certificate/key
  -nocert               Don't include certificate in output (key only)
  -nokey                Don't include private key in output (certificate only)
  -export-password password
                        Password to protect the output PFX/P12 file
```

---

### `find -h`

```text
$ certipy find -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy find [-h] [-text] [-stdout] [-json] [-csv] [-output prefix] [-enabled] [-dc-only] [-vulnerable] [-oids] [-hide-admins] [-sid object sid] [-dn distinguished name]
                    [-dc-ip ip address] [-dc-host hostname] [-target-ip ip address] [-target dns/ip address] [-ns ip address] [-dns-tcp] [-timeout seconds] [-u username@domain]
                    [-p password] [-hashes [lmhash:]nthash] [-k] [-aes hex key] [-no-pass] [-ldap-scheme ldap scheme] [-ldap-port port] [-no-ldap-channel-binding] [-no-ldap-signing]
                    [-ldap-simple-auth] [-ldap-user-dn dn]

Discover and analyze AD CS components. This command identifies vulnerable certificate templates, security misconfigurations, and potential
certificate-based privilege escalation paths.

options:
  -h, --help            show this help message and exit

output options:
  -text                 Output result as formatted text file
  -stdout               Output result as text directly to console
  -json                 Output result as JSON
  -csv                  Output result as CSV
  -output prefix        Filename prefix for writing results to

find options:
  -enabled              Show only enabled certificate templates
  -dc-only              Collects data only from the domain controller. Will not try to retrieve CA security/configuration or check for Web Enrollment
  -vulnerable           Show only vulnerable certificate templates based on nested group memberships
  -oids                 Show OIDs (Issuance Policies) and their properties
  -hide-admins          Don't show administrator permissions for -text, -stdout, -json, and -csv

identity options:
  -sid object sid       SID of the user provided in the command line. Useful for cross domain authentication
  -dn distinguished name
                        Distinguished name of the user provided in the command line. Useful for cross domain authentication

connection options:
  -dc-ip ip address     IP address of the domain controller. If omitted, it will use the domain part (FQDN) specified in the target parameter
  -dc-host hostname     Hostname of the domain controller. Required for Kerberos authentication during certain operations. If omitted, the domain part (FQDN) specified in the account
                        parameter will be used
  -target-ip ip address
                        IP address of the target machine. If omitted, it will use whatever was specified as target. Useful when target is the NetBIOS name and cannot be resolved
  -target dns/ip address
                        DNS name or IP address of the target machine. Required for Kerberos authentication
  -ns ip address        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections in seconds (default: 10)

authentication options:
  -u username@domain, -username username@domain
                        Username to authenticate with
  -p password, -password password
                        Password for authentication
  -hashes [lmhash:]nthash
                        NTLM hash
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
  -no-pass              Don't ask for password (useful for -k)

ldap options:
  -ldap-scheme ldap scheme
                        LDAP connection scheme to use (default: ldaps)
  -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
  -no-ldap-channel-binding
                        Don't use LDAP channel binding for LDAP communication (LDAPS only)
  -no-ldap-signing      Don't use LDAP signing for LDAP communication (LDAP only)
  -ldap-simple-auth     Use SIMPLE LDAP authentication instead of NTLM
  -ldap-user-dn dn      Distinguished Name of target account for LDAP authentication
```

---

### `parse -h`

```text
$ certipy parse -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy parse [-h] [-text] [-stdout] [-json] [-csv] [-output prefix] [-format format] [-domain domain name] [-ca ca name] [-sids sids] [-published templates] [-enabled]
                     [-vulnerable] [-hide-admins]
                     file

Parse and analyze certificate templates from exported registry data. This allows assessment of AD CS security without direct domain access.

positional arguments:
  file                  File to parse (BOF output or .reg file from registry export)

options:
  -h, --help            show this help message and exit

output options:
  -text                 Output result as formatted text file
  -stdout               Output result as text directly to console
  -json                 Output result as JSON
  -csv                  Output result as CSV
  -output prefix        Filename prefix for writing results to

parse options:
  -format format        Input format: BOF output or Windows .reg file (default: bof)
  -domain domain name   Domain name. Only used for output context (default: UNKNOWN)
  -ca ca name           CA name. Only used for output context (default: UNKNOWN)
  -sids sids            Consider the comma separated list of SIDs as owned for vulnerability assessment
  -published templates  Consider the comma separated list of template names as published in AD

filter options:
  -enabled              Show only enabled certificate templates
  -vulnerable           Show only vulnerable certificate templates based on nested group memberships
  -hide-admins          Don't show administrator permissions for -text, -stdout, -json, and -csv output
```

---

### `forge -h`

```text
$ certipy forge -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy forge [-h] [-ca-pfx pfx/p12 file name] [-ca-password password] [-upn alternative UPN] [-dns alternative DNS] [-sid alternative Object SID] [-subject subject]
                     [-template pfx/p12 file name] [-issuer issuer] [-crl ldap path] [-serial serial number] [-application-policies Application Policy [Application Policy ...]]
                     [-smime encryption algorithm] [-key-size RSA key length] [-validity-period days] [-out output file name] [-pfx-password password]

Forge certificates using a compromised CA certificate or generate a self-signed CA. This allows creating certificates for any identity in the domain or creating standalone certificate
chains.

options:
  -h, --help            show this help message and exit
  -ca-pfx pfx/p12 file name
                        Path to CA certificate and private key (PFX/P12 format). If not specified, a self-signed root CA will be generated
  -ca-password password
                        Password for the CA PFX file

subject alternative name options:
  -upn alternative UPN  User Principal Name to include in the Subject Alternative Name
  -dns alternative DNS  DNS name to include in the Subject Alternative Name
  -sid alternative Object SID
                        Object SID to include in the Subject Alternative Name
  -subject subject      Subject to include in certificate, e.g. CN=Administrator,CN=Users,DC=CORP,DC=LOCAL

certificate content options:
  -template pfx/p12 file name
                        Path to template certificate to clone properties from
  -issuer issuer        Issuer to include in certificate. If not specified, the issuer from the CA cert will be used
  -crl ldap path        LDAP path to a CRL distribution point
  -serial serial number
                        Custom serial number for the certificate
  -application-policies Application Policy [Application Policy ...]
                        Specify application policies for the certificate request using OIDs (e.g., '1.3.6.1.4.1.311.10.3.4' or 'Client Authentication')
  -smime encryption algorithm
                        Specify SMIME Extension that gets added to CSR (e.g., des, rc4, 3des, aes128, aes192, aes256)

key options:
  -key-size RSA key length
                        Length of RSA key (default: 2048)

validity options:
  -validity-period days
                        Validity period in days (default: 365)

output options:
  -out output file name
                        Path to save the forged certificate and private key (PFX format)
  -pfx-password password
                        Password to protect the output PFX file
```

---

### `relay -h`

```text
$ certipy relay -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy relay [-h] -target protocol://<ip address or hostname> [-ca certificate authority name] [-template template name] [-upn alternative UPN] [-dns alternative DNS]
                     [-sid alternative Object SID] [-subject subject] [-retrieve request ID] [-key-size RSA key length] [-archive-key cax cert file] [-pfx-password PFX file password]
                     [-application-policies Application Policy [Application Policy ...]] [-smime encryption algorithm] [-out output file name] [-interface ip address] [-port port number]
                     [-forever] [-no-skip] [-enum-templates] [-timeout seconds]

Perform NTLM relay attacks against Active Directory Certificate Services. This allows obtaining certificates for relayed users and computers, which can be used for authentication and
potential privilege escalation.

options:
  -h, --help            show this help message and exit
  -target protocol://<ip address or hostname>
                        protocol://<IP address or hostname> of certificate authority. Example: http://CA.CORP.LOCAL for ESC8 or rpc://CA.CORP.LOCAL for ESC11

certificate request options:
  -ca certificate authority name
                        CA name to request certificate from. Example: 'CORP-CA'. Only required for RPC relay (ESC11)
  -template template name
                        If omitted, the template 'Machine' or 'User' is chosen by default depending on whether the relayed account name ends with '$'. Relaying a DC should require
                        specifying the 'DomainController' template
  -upn alternative UPN  User Principal Name to include in the Subject Alternative Name
  -dns alternative DNS  DNS name to include in the Subject Alternative Name
  -sid alternative Object SID
                        Object SID to include in the Subject Alternative Name
  -subject subject      Subject to include in certificate, e.g. CN=Administrator,CN=Users,DC=CORP,DC=LOCAL
  -retrieve request ID  Retrieve an issued certificate specified by a request ID instead of requesting a new certificate
  -key-size RSA key length
                        Length of RSA key (default: 2048)
  -archive-key cax cert file
                        Specify CAX Certificate for Key Archival. You can request the cax cert with 'certipy req -cax-cert'
  -pfx-password PFX file password
                        Password for the PFX file
  -application-policies Application Policy [Application Policy ...]
                        Specify application policies for the certificate request using OIDs (e.g., '1.3.6.1.4.1.311.10.3.4' or 'Client Authentication')
  -smime encryption algorithm
                        Specify SMIME Extension that gets added to CSR (e.g., des, rc4, 3des, aes128, aes192, aes256)

output options:
  -out output file name
                        Path to save the certificate and private key (PFX format)

server options:
  -interface ip address
                        IP Address of interface to listen on (default: 0.0.0.0)
  -port port number     Port to listen on (default: 445)

relay options:
  -forever              Don't stop the relay server after the first successful relay
  -no-skip              Don't skip previously attacked users (use with -forever)
  -enum-templates       Relay to /certsrv/certrqxt.asp and parse available certificate templates

connection options:
  -timeout seconds      Timeout for connections in seconds (default: 10)
```

---

### `req -h`

```text
$ certipy req -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy req [-h] [-ca certificate authority name] [-template template name] [-upn alternative UPN] [-dns alternative DNS] [-sid alternative Object SID] [-subject subject]
                   [-retrieve request ID] [-on-behalf-of domain\account] [-pfx pfx/p12 file name] [-pfx-password PFX file password] [-key-size RSA key length] [-archive-key] [-cax-cert]
                   [-renew] [-application-policies Application Policy [Application Policy ...]] [-smime encryption algorithm] [-out output file name] [-web] [-dcom] [-dynamic-endpoint]
                   [-http-scheme http scheme] [-http-port port number] [-no-channel-binding] [-dc-ip ip address] [-dc-host hostname] [-target-ip ip address] [-target dns/ip address]
                   [-ns ip address] [-dns-tcp] [-timeout seconds] [-u username@domain] [-p password] [-hashes [lmhash:]nthash] [-k] [-aes hex key] [-no-pass] [-ldap-scheme ldap scheme]
                   [-ldap-port port] [-no-ldap-channel-binding] [-no-ldap-signing] [-ldap-simple-auth] [-ldap-user-dn dn]

Request and retrieve certificates from AD CS. This command supports multiple enrollment protocols and certificate template types.

options:
  -h, --help            show this help message and exit
  -ca certificate authority name
                        Name of the Certificate Authority to request certificates from. Required for RPC and DCOM methods

certificate request options:
  -template template name
                        Certificate template to request (default: User)
  -upn alternative UPN  User Principal Name to include in the Subject Alternative Name
  -dns alternative DNS  DNS name to include in the Subject Alternative Name
  -sid alternative Object SID
                        Object SID to include in the Subject Alternative Name
  -subject subject      Subject to include in certificate, e.g. CN=Administrator,CN=Users,DC=CORP,DC=LOCAL
  -retrieve request ID  Retrieve an issued certificate specified by a request ID instead of requesting a new certificate
  -on-behalf-of domain\account
                        Use a Certificate Request Agent certificate to request on behalf of another user
  -pfx pfx/p12 file name
                        Path to PFX for -on-behalf-of or -renew
  -pfx-password PFX file password
                        Password for the PFX file
  -key-size RSA key length
                        Length of RSA key (default: 2048)
  -archive-key          Send private key for Key Archival
  -cax-cert             Retrieve CAX Cert for relay with enabled Key Archival
  -renew                Create renewal request
  -application-policies Application Policy [Application Policy ...]
                        Specify application policies for the certificate request using OIDs (e.g., '1.3.6.1.4.1.311.10.3.4' or 'Client Authentication')
  -smime encryption algorithm
                        Specify SMIME Extension that gets added to CSR (e.g., des, rc4, 3des, aes128, aes192, aes256)

output options:
  -out output file name
                        Path to save the certificate and private key (PFX format)

connection options:
  -web                  Use Web Enrollment instead of RPC
  -dcom                 Use DCOM Enrollment instead of RPC
  -dc-ip ip address     IP address of the domain controller. If omitted, it will use the domain part (FQDN) specified in the target parameter
  -dc-host hostname     Hostname of the domain controller. Required for Kerberos authentication during certain operations. If omitted, the domain part (FQDN) specified in the account
                        parameter will be used
  -target-ip ip address
                        IP address of the target machine. If omitted, it will use whatever was specified as target. Useful when target is the NetBIOS name and cannot be resolved
  -target dns/ip address
                        DNS name or IP address of the target machine. Required for Kerberos authentication
  -ns ip address        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections in seconds (default: 10)

rpc connection options:
  -dynamic-endpoint     Prefer dynamic TCP endpoint over named pipe

http connection options:
  -http-scheme http scheme
                        HTTP scheme to use for Web Enrollment (default: http)
  -http-port port number
                        Web Enrollment port (default: 80 for http, 443 for https)
  -no-channel-binding   Disable channel binding for HTTP connections

authentication options:
  -u username@domain, -username username@domain
                        Username to authenticate with
  -p password, -password password
                        Password for authentication
  -hashes [lmhash:]nthash
                        NTLM hash
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
  -no-pass              Don't ask for password (useful for -k)

ldap options:
  -ldap-scheme ldap scheme
                        LDAP connection scheme to use (default: ldaps)
  -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
  -no-ldap-channel-binding
                        Don't use LDAP channel binding for LDAP communication (LDAPS only)
  -no-ldap-signing      Don't use LDAP signing for LDAP communication (LDAP only)
  -ldap-simple-auth     Use SIMPLE LDAP authentication instead of NTLM
  -ldap-user-dn dn      Distinguished Name of target account for LDAP authentication
```

---

### `shadow -h`

```text
$ certipy shadow -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy shadow [-h] [-account target account] [-device-id device id] [-out output file name] [-dc-ip ip address] [-dc-host hostname] [-target-ip ip address]
                      [-target dns/ip address] [-ns ip address] [-dns-tcp] [-timeout seconds] [-u username@domain] [-p password] [-hashes [lmhash:]nthash] [-k] [-aes hex key] [-no-pass]
                      [-ldap-scheme ldap scheme] [-ldap-port port] [-no-ldap-channel-binding] [-no-ldap-signing] [-ldap-simple-auth] [-ldap-user-dn dn]
                      {list,add,remove,clear,info,auto}

Manipulate Key Credential Links (Shadow Credentials) on Active Directory accounts. This allows for account takeover by adding or modifying Key Credential Links.

positional arguments:
  {list,add,remove,clear,info,auto}
                        Operation to perform on Key Credential Links: list (view all), add (create new), remove (delete specific), clear (remove all), info (display detailed
                        information), auto (automatically exploit)

options:
  -h, --help            show this help message and exit

account options:
  -account target account
                        Account to target. If omitted, the user specified in the target will be used
  -device-id device id  Device ID of the Key Credential Link to target

output options:
  -out output file name
                        Output file for saving certificate or results

connection options:
  -dc-ip ip address     IP address of the domain controller. If omitted, it will use the domain part (FQDN) specified in the target parameter
  -dc-host hostname     Hostname of the domain controller. Required for Kerberos authentication during certain operations. If omitted, the domain part (FQDN) specified in the account
                        parameter will be used
  -target-ip ip address
                        IP address of the target machine. If omitted, it will use whatever was specified as target. Useful when target is the NetBIOS name and cannot be resolved
  -target dns/ip address
                        DNS name or IP address of the target machine. Required for Kerberos authentication
  -ns ip address        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections in seconds (default: 10)

authentication options:
  -u username@domain, -username username@domain
                        Username to authenticate with
  -p password, -password password
                        Password for authentication
  -hashes [lmhash:]nthash
                        NTLM hash
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
  -no-pass              Don't ask for password (useful for -k)

ldap options:
  -ldap-scheme ldap scheme
                        LDAP connection scheme to use (default: ldaps)
  -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
  -no-ldap-channel-binding
                        Don't use LDAP channel binding for LDAP communication (LDAPS only)
  -no-ldap-signing      Don't use LDAP signing for LDAP communication (LDAP only)
  -ldap-simple-auth     Use SIMPLE LDAP authentication instead of NTLM
  -ldap-user-dn dn      Distinguished Name of target account for LDAP authentication
```

---

### `template -h`

```text
$ certipy template -h
Certipy v5.0.0 - by Oliver Lyak (ly4k)

usage: certipy template [-h] -template template name [-write-configuration configuration file] [-write-default-configuration] [-save-configuration configuration file] [-no-save] [-force]
                        [-dc-ip ip address] [-dc-host hostname] [-target-ip ip address] [-target dns/ip address] [-ns ip address] [-dns-tcp] [-timeout seconds] [-u username@domain]
                        [-p password] [-hashes [lmhash:]nthash] [-k] [-aes hex key] [-no-pass] [-ldap-scheme ldap scheme] [-ldap-port port] [-no-ldap-channel-binding] [-no-ldap-signing]
                        [-ldap-simple-auth] [-ldap-user-dn dn]

Manipulate certificate templates in Active Directory. This command allows viewing and modifying template configurations for privilege escalation testing or remediation.

options:
  -h, --help            show this help message and exit
  -template template name
                        Name of the certificate template to operate on (case-sensitive)

configuration options:
  -write-configuration configuration file
                        Apply configuration from a JSON file to the certificate template. Use this option to restore a previous configuration or apply custom settings. The file should
                        contain the template configuration in valid JSON format.
  -write-default-configuration
                        Apply the default Certipy ESC1 configuration to the certificate template. This configures the template to be vulnerable to ESC1 attack.
  -save-configuration configuration file
                        Save the current template configuration to a JSON file. This creates a backup before making changes or documents the current settings. If not specified when using
                        -write-configuration or -write-default-configuration, a backup will still be created.
  -no-save              Skip saving the current template configuration before applying changes. Use this option to apply modifications without creating a backup file.
  -force                Don't prompt for confirmation before applying changes. Use this option to apply modifications without user interaction.

connection options:
  -dc-ip ip address     IP address of the domain controller. If omitted, it will use the domain part (FQDN) specified in the target parameter
  -dc-host hostname     Hostname of the domain controller. Required for Kerberos authentication during certain operations. If omitted, the domain part (FQDN) specified in the account
                        parameter will be used
  -target-ip ip address
                        IP address of the target machine. If omitted, it will use whatever was specified as target. Useful when target is the NetBIOS name and cannot be resolved
  -target dns/ip address
                        DNS name or IP address of the target machine. Required for Kerberos authentication
  -ns ip address        Nameserver for DNS resolution
  -dns-tcp              Use TCP instead of UDP for DNS queries
  -timeout seconds      Timeout for connections in seconds (default: 10)

authentication options:
  -u username@domain, -username username@domain
                        Username to authenticate with
  -p password, -password password
                        Password for authentication
  -hashes [lmhash:]nthash
                        NTLM hash
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aes hex key          AES key to use for Kerberos Authentication (128 or 256 bits)
  -no-pass              Don't ask for password (useful for -k)

ldap options:
  -ldap-scheme ldap scheme
                        LDAP connection scheme to use (default: ldaps)
  -ldap-port port       Port for LDAP communication (default: 636 for ldaps, 389 for ldap)
  -no-ldap-channel-binding
                        Don't use LDAP channel binding for LDAP communication (LDAPS only)
  -no-ldap-signing      Don't use LDAP signing for LDAP communication (LDAP only)
  -ldap-simple-auth     Use SIMPLE LDAP authentication instead of NTLM
  -ldap-user-dn dn      Distinguished Name of target account for LDAP authentication
```
