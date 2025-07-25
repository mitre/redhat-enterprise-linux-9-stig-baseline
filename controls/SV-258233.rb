control 'SV-258233' do
  title 'RHEL 9 pam_unix.so module must be configured in the password-auth file to use a FIPS 140-3 approved cryptographic hashing algorithm for system authentication.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and; therefore, cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised.

RHEL 9 systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-3 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DOD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.'
  desc 'check', 'Verify that the pam_unix.so module is configured to use sha512 in /etc/pam.d/password-auth with the following command:

$ grep "^password.*pam_unix.so.*sha512" /etc/pam.d/password-auth

password sufficient pam_unix.so sha512

If "sha512" is missing, or the line is commented out, this is a finding.

If the system administrator (SA) can demonstrate that the required configuration is contained in a PAM configuration file included or substacked from the system-auth file, this is not a finding.'
  desc 'fix', 'Configure RHEL 9 to use a FIPS 140-3 approved cryptographic hashing algorithm for system authentication.

Edit/modify the following line in the "/etc/pam.d/password-auth" file to include the sha512 option for pam_unix.so:

password sufficient pam_unix.so sha512'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag gid: 'V-258233'
  tag rid: 'SV-258233r1015136_rule'
  tag stig_id: 'RHEL-09-671025'
  tag fix_id: 'F-61898r926685_fix'
  tag cci: ['CCI-000803', 'CCI-000196', 'CCI-004062']
  tag nist: ['IA-7', 'IA-5 (1) (c)', 'IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  pam_auth_files = input('pam_auth_files')

  describe pam(pam_auth_files['system-auth']) do
    its('lines') { should match_pam_rule('password sufficient pam_unix.so sha512') }
  end
end
