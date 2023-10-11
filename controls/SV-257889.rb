control 'SV-257889' do
  title 'All RHEL 9 local initialization files must have mode 0740 or less permissive.'
  desc "Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Verify that all local initialization files have a mode of "0740" or less permissive with the following command:

Note: The example will be for the "wadea" user, who has a home directory of "/home/wadea".

$ sudo ls -al /home/wadea/.[^.]* | more

-rwxr-xr-x 1 wadea users 896 Mar 10 2011 .profile
-rwxr-xr-x 1 wadea users 497 Jan 6 2007 .login
-rwxr-xr-x 1 wadea users 886 Jan 6 2007 .something

If any local initialization files have a mode more permissive than "0740", this is a finding.'
  desc 'fix', 'Set the mode of the local initialization files to "0740" with the following command:

Note: The example will be for the wadea user, who has a home directory of "/home/wadea".

$ sudo chmod 0740 /home/wadea/.<INIT_FILE>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61630r925652_chk'
  tag severity: 'medium'
  tag gid: 'V-257889'
  tag rid: 'SV-257889r925654_rule'
  tag stig_id: 'RHEL-09-232045'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61554r925653_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
