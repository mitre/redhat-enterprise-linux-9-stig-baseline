control 'SV-258123' do
  title 'RHEL 9 must implement certificate status checking for multifactor authentication.'
  desc 'Using an authentication device, such as a DOD Common Access Card (CAC) or token that is separate from the information system, ensures that even if the information system is compromised, credentials stored on the authentication device will not be affected.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification (PIV) card and the DOD CAC.

RHEL 9 includes multiple options for configuring certificate status checking, but for this requirement focuses on the System Security Services Daemon (SSSD). By default, SSSD performs Online Certificate Status Protocol (OCSP) checking and certificate verification using a sha256 digest function.

'
  desc 'check', 'Verify the operating system implements Online Certificate Status Protocol (OCSP) and is using the proper digest value on the system with the following command:

$ sudo grep certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf | grep -v "^#"

certificate_verification = ocsp_dgst=sha512

If the certificate_verification line is missing from the [sssd] section, or is missing "ocsp_dgst=sha512", ask the administrator to indicate what type of multifactor authentication is being utilized and how the system implements certificate status checking. If there is no evidence of certificate status checking being used, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to implement certificate status checking for multifactor authentication.

Review the "/etc/sssd/conf.d/certificate_verification.conf" file to determine if the system is configured to prevent OCSP or certificate verification.

Add the following line to the "/etc/sssd/conf.d/certificate_verification.conf" file:

certificate_verification = ocsp_dgst=sha512

Set the correct ownership and permissions on the "/etc/sssd/conf.d/certificate_verification.conf" file by running these commands:

$ sudo chown root:root "/etc/sssd/conf.d/certificate_verification.conf"
$ sudo chmod 600 "/etc/sssd/conf.d/certificate_verification.conf"

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

$ sudo systemctl restart sssd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61864r926354_chk'
  tag severity: 'medium'
  tag gid: 'V-258123'
  tag rid: 'SV-258123r926356_rule'
  tag stig_id: 'RHEL-09-611170'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-61788r926355_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000377-GPOS-00162']
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-001954']
  tag nist: ['IA-2 (11)', 'IA-2 (12)']
end
