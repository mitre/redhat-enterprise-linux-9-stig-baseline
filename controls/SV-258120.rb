control 'SV-258120' do
  title 'RHEL 9 must not have accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', "Verify that null or blank passwords cannot be used with the following command:

$ sudo awk -F: '!$2 {print $1}' /etc/shadow

If the command returns any results, this is a finding."
  desc 'fix', 'Configure all accounts on RHEL 9 to have a password or lock the account with the following commands:

Perform a password reset:

$ sudo passwd [username] 

To lock an account:

$ sudo passwd -l [username]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61861r926345_chk'
  tag severity: 'medium'
  tag gid: 'V-258120'
  tag rid: 'SV-258120r926347_rule'
  tag stig_id: 'RHEL-09-611155'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61785r926346_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
