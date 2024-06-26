control 'SV-258117' do
  title 'RHEL 9 must be configured to use the shadow file to store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords that are encrypted with a weak algorithm are no more protected than if they are kept in plain text.

This setting ensures user and group account administration utilities are configured to store only encrypted representations of passwords. Additionally, the "crypt_style" configuration option ensures the use of a strong hashing algorithm that makes password cracking attacks more difficult.'
  desc 'check', %q(Verify the system's shadow file is configured to store only encrypted representations of passwords with a hash value of SHA512 with the following command:

# grep -i encrypt_method /etc/login.defs

ENCRYPT_METHOD SHA512

If "ENCRYPT_METHOD" does not have a value of "SHA512", or the line is commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to store only SHA512 encrypted representations of passwords.

Add or update the following line in the "/etc/login.defs" file:

ENCRYPT_METHOD SHA512'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61858r926336_chk'
  tag severity: 'medium'
  tag gid: 'V-258117'
  tag rid: 'SV-258117r926338_rule'
  tag stig_id: 'RHEL-09-611140'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-61782r926337_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
  tag 'host', 'container'

  describe login_defs do
    its('ENCRYPT_METHOD') { should cmp 'SHA512' }
  end
end
