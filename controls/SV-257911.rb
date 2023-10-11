control 'SV-257911' do
  title 'RHEL 9 /etc/shadow file must be group-owned by root.'
  desc 'The "/etc/shadow" file stores password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify the group ownership of the "/etc/shadow" file with the following command:

$ sudo stat -c "%G %n" /etc/shadow 

root /etc/shadow

If "/etc/shadow" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Change the group of the file /etc/shadow to root by running the following command:

$ sudo chgrp root /etc/shadow'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61652r925718_chk'
  tag severity: 'medium'
  tag gid: 'V-257911'
  tag rid: 'SV-257911r925720_rule'
  tag stig_id: 'RHEL-09-232155'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61576r925719_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
