control 'SV-258130' do
  title 'RHEL 9 must prevent system daemons from using Kerberos for authentication.'
  desc 'Unapproved mechanisms used for authentication to the cryptographic module are not verified; therefore, cannot be relied upon to provide confidentiality or integrity and DOD data may be compromised.

RHEL 9 systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

The key derivation function (KDF) in Kerberos is not FIPS compatible. Ensuring the system does not have any keytab files present prevents system daemons from using Kerberos for authentication. A keytab is a file containing pairs of Kerberos principals and encrypted keys.

FIPS 140-3 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DOD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.'
  desc 'check', %q(Verify that RHEL 9 prevents system daemons from using Kerberos for authentication with the following command:

$ sudo ls -al /etc/*.keytab

ls: cannot access '/etc/*.keytab': No such file or directory 

If this command produces any "keytab" file(s), this is a finding.)
  desc 'fix', 'Configure RHEL 9 to prevent system daemons from using Kerberos for authentication.

Remove any files with the .keytab extension from the operating system.

rm -f /etc/*.keytab'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61871r926375_chk'
  tag severity: 'medium'
  tag gid: 'V-258130'
  tag rid: 'SV-258130r926377_rule'
  tag stig_id: 'RHEL-09-611205'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-61795r926376_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
