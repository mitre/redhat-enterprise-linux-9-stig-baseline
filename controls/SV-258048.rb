control 'SV-258048' do
  title 'All RHEL 9 interactive users must have a primary group that exists.'
  desc 'If a user is assigned the Group Identifier (GID) of a group that does not exist on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group.'
  desc 'check', 'Verify that all RHEL 9 interactive users have a valid GID.

Check that the interactive users have a valid GID with the following command:
 
$ sudo pwck -qr 
 
If the system has any interactive users with duplicate GIDs, this is a finding.'
  desc 'fix', %q(Configure the system so that all GIDs are referenced in "/etc/passwd" are defined in "/etc/group".

Edit the file "/etc/passwd" and ensure that every user's GID is a valid GID.)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61789r926129_chk'
  tag severity: 'medium'
  tag gid: 'V-258048'
  tag rid: 'SV-258048r926131_rule'
  tag stig_id: 'RHEL-09-411045'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-61713r926130_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
