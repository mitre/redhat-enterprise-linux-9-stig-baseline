control 'SV-258231' do
  title 'RHEL 9 must employ FIPS 140-3 approved cryptographic hashing algorithms for all stored passwords.'
  desc 'The system must use a strong hashing algorithm to store the password.

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

'
  desc 'check', 'Verify that the interactive user account passwords are using a strong password hash with the following command:

$ sudo cut -d: -f2 /etc/shadow

$6$kcOnRq/5$NUEYPuyL.wghQwWssXRcLRFiiru7f5JPV6GaJhNC2aK5F3PZpE/BCCtwrxRc/AInKMNX3CdMw11m9STiql12f/ 

Password hashes "!" or "*" indicate inactive accounts not available for logon and are not evaluated.

If any interactive user password hash does not begin with "$6", this is a finding.'
  desc 'fix', 'Lock all interactive user accounts not using SHA-512 hashing until the passwords can be regenerated with SHA-512.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61972r926678_chk'
  tag severity: 'medium'
  tag gid: 'V-258231'
  tag rid: 'SV-258231r926680_rule'
  tag stig_id: 'RHEL-09-671015'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-61896r926679_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag cci: ['CCI-000196', 'CCI-000803']
  tag nist: ['IA-5 (1) (c)', 'IA-7']
end
