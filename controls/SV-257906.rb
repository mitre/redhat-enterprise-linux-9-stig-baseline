control 'SV-257906' do
  title 'RHEL 9 /etc/passwd file must be owned by root.'
  desc 'The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.'
  desc 'check', 'Verify the ownership of the "/etc/passwd" file with the following command:

$ sudo stat -c "%U %n" /etc/passwd

root /etc/passwd

If "/etc/passwd" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Change the owner of the file /etc/passwd to root by running the following command:

$ sudo chown root /etc/passwd'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61647r925703_chk'
  tag severity: 'medium'
  tag gid: 'V-257906'
  tag rid: 'SV-257906r925705_rule'
  tag stig_id: 'RHEL-09-232130'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61571r925704_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
