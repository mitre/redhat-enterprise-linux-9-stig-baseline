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
  tag rid: 'SV-258048r958482_rule'
  tag stig_id: 'RHEL-09-411045'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-61713r926130_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
  tag 'host'
  tag 'container'

  ignore_shells = input('non_interactive_shells').join('|')
  interactive_users = passwd.where { uid.to_i >= 1000 && !shell.match(ignore_shells) }.users
  interactive_users_without_group = interactive_users.reject { |u| group(user(u).group).exists? }

  describe 'Interactive users' do
    it 'should have a valid primary group' do
      expect(interactive_users_without_group).to be_empty, "Interactive users without a valid primary group:\n\t- #{interactive_users_without_group.join("\n\t- ")}"
    end
  end
end
