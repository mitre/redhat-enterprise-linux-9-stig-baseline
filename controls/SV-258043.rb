control 'SV-258043' do
  title 'All RHEL 9 local interactive user accounts must be assigned a home directory upon creation.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', 'Verify all local interactive users on RHEL 9 are assigned a home directory upon creation with the following command:

$ grep -i create_home /etc/login.defs

CREATE_HOME yes

If the value for "CREATE_HOME" parameter is not set to "yes", the line is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to assign home directories to all new local interactive users by setting the "CREATE_HOME" parameter in "/etc/login.defs" to "yes" as follows.

CREATE_HOME yes'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61784r926114_chk'
  tag severity: 'medium'
  tag gid: 'V-258043'
  tag rid: 'SV-258043r926116_rule'
  tag stig_id: 'RHEL-09-411020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61708r926115_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
