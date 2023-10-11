control 'SV-258099' do
  title 'RHEL 9 password-auth must be configured to use a sufficient number of hashing rounds.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords that are encrypted with a weak algorithm are no more protected than if they are kept in plain text.

Using more hashing rounds makes password cracking attacks more difficult.

'
  desc 'check', 'Verify the number of rounds for the password hashing algorithm is configured with the following command:

$ sudo grep rounds /etc/pam.d/password-auth

password sufficient pam_unix.so sha512 rounds=5000

If a matching line is not returned or "rounds" is less than "5000", this a finding.'
  desc 'fix', 'Configure Red Hat Enterprise Linux 9 to use 5000 hashing rounds for hashing passwords.

Add or modify the following line in "/etc/pam.d/password-auth" and set "rounds" to "5000".

password sufficient pam_unix.so sha512 rounds=5000'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61840r926282_chk'
  tag severity: 'medium'
  tag gid: 'V-258099'
  tag rid: 'SV-258099r926284_rule'
  tag stig_id: 'RHEL-09-611050'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-61764r926283_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag cci: ['CCI-000196', 'CCI-000803']
  tag nist: ['IA-5 (1) (c)', 'IA-7']
end
