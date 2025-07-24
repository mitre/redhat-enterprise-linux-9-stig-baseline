control 'SV-258116' do
  title 'RHEL 9 must be configured so that user and group account administration utilities are configured to store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords that are encrypted with a weak algorithm are no more protected than if they are kept in plain text.

This setting ensures user and group account administration utilities are configured to store only encrypted representations of passwords. Additionally, the "crypt_style" configuration option ensures the use of a strong hashing algorithm that makes password cracking attacks more difficult.'
  desc 'check', 'Verify the user and group account administration utilities are configured to store only encrypted representations of passwords with the following command:

$ grep crypt_style /etc/libuser.conf 

crypt_style = sha512

If the "crypt_style" variable is not set to "sha512", is not in the defaults section, is commented out, or does not exist, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to use the SHA-512 algorithm for password hashing.

Add or change the following line in the "[defaults]" section of "/etc/libuser.conf" file:

crypt_style = sha512'
  impact 0.5
  tag check_id: 'C-61857r1045239_chk'
  tag severity: 'medium'
  tag gid: 'V-258116'
  tag rid: 'SV-258116r1045240_rule'
  tag stig_id: 'RHEL-09-611135'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-61781r1014895_fix'
  tag 'documentable'
  tag cci: ['CCI-000196', 'CCI-004062']
  tag nist: ['IA-5 (1) (c)', 'IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/libuser.conf') do
    its('defaults.crypt_style') { should cmp 'sha512' }
  end
end
