control 'SV-258119' do
  title 'RHEL 9 shadow password suite must be configured to use a sufficient number of hashing rounds.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords that are encrypted with a weak algorithm are no more protected than if they are kept in plain text.

Using more hashing rounds makes password cracking attacks more difficult.

'
  desc 'check', 'Verify that RHEL 9 has a minimum number of hash rounds configured with the following command:

$ grep -i sha_crypt /etc/login.defs

If "SHA_CRYPT_MIN_ROUNDS" or "SHA_CRYPT_MAX_ROUNDS" is less than "5000", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to encrypt all stored passwords with a strong cryptographic hash.

Edit/modify the following line in the "/etc/login.defs" file and set "SHA_CRYPT_MIN_ROUNDS" to a value no lower than "5000":

SHA_CRYPT_MIN_ROUNDS 5000'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61860r926342_chk'
  tag severity: 'medium'
  tag gid: 'V-258119'
  tag rid: 'SV-258119r926344_rule'
  tag stig_id: 'RHEL-09-611150'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-61784r926343_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag cci: ['CCI-000196', 'CCI-000803']
  tag nist: ['IA-5 (1) (c)', 'IA-7']
end
