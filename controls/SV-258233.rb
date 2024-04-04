control 'SV-258233' do
  title 'The RHEL 8 pam_unix.so module must be configured in the system-auth
file to use a FIPS 140-2 approved cryptographic hashing algorithm for system
authentication.'
  desc 'Unapproved mechanisms that are used for authentication to the
cryptographic module are not verified and therefore cannot be relied upon to
provide confidentiality or integrity, and DoD data may be compromised.

    RHEL 8 systems utilizing encryption are required to use FIPS-compliant
mechanisms for authenticating to cryptographic modules.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD
requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
general-purpose computing system.'
  desc 'check', 'Verify that pam_unix.so module is configured to use sha512.

Check that pam_unix.so module is configured to use sha512 in /etc/pam.d/system-auth with the following command:

$ sudo grep password /etc/pam.d/system-auth | grep pam_unix

password sufficient pam_unix.so sha512

If "sha512" is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.

Edit/modify the following line in the "/etc/pam.d/system-auth" file to include the sha512 option for pam_unix.so:

password sufficient pam_unix.so sha512'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag gid: 'V-244524'
  tag rid: 'SV-258233r809331_rule'
  tag stig_id: 'RHEL-08-010159'
  tag fix_id: 'F-47756r809330_fix'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
  tag 'host'
  tag 'container'

  pam_auth_files = input('pam_auth_files')

  describe pam(pam_auth_files['system-auth']) do
    its('lines') { should match_pam_rule('password sufficient pam_unix.so sha512') }
  end
end
