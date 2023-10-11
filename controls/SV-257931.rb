control 'SV-257931' do
  title 'All RHEL 9 local files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same user identifier "UID" as the UID of the unowned files.'
  desc 'check', "Verify all local files and directories on RHEL 9 have a valid owner with the following command:

$ df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nouser

If any files on the system do not have an assigned owner, this is a finding."
  desc 'fix', 'Either remove all files and directories from the system that do not have a valid user, or assign a valid user to all unowned files and directories on RHEL 9 with the "chown" command:

$ sudo chown <user> <file>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61672r925778_chk'
  tag severity: 'medium'
  tag gid: 'V-257931'
  tag rid: 'SV-257931r925780_rule'
  tag stig_id: 'RHEL-09-232255'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61596r925779_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
