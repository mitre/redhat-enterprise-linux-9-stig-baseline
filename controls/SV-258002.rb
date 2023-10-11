control 'SV-258002' do
  title 'RHEL 9 SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', 'Verify the SSH daemon performs compression after a user successfully authenticates with the following command:

$ sudo grep -ir compression /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*

Compression delayed

If the "Compression" keyword is set to "yes", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to not allow compression.

Uncomment the "Compression" keyword in "/etc/ssh/sshd_config" on the system and set the value to "delayed" or "no":

Compression no

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61743r925991_chk'
  tag severity: 'medium'
  tag gid: 'V-258002'
  tag rid: 'SV-258002r925993_rule'
  tag stig_id: 'RHEL-09-255130'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61667r925992_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
