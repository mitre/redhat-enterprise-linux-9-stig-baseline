control 'SV-257997' do
  title 'RHEL 9 SSH server configuration file must be group-owned by root.'
  desc 'Service configuration files enable or disable features of their respective services, which if configured incorrectly, can lead to insecure and vulnerable configurations. Therefore, service configuration files must be owned by the correct group to prevent unauthorized changes.'
  desc 'check', 'Verify the group ownership of the "/etc/ssh/sshd_config" file with the following command:

$ ls -al /etc/ssh/sshd_config

rw-------. 1 root root 3669 Feb 22 11:34 /etc/ssh/sshd_config

If the "/etc/ssh/sshd_config" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure the "/etc/ssh/sshd_config" file to be group-owned by root with the following command:

$ sudo chgrp root /etc/ssh/sshd_config'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61738r925976_chk'
  tag severity: 'medium'
  tag gid: 'V-257997'
  tag rid: 'SV-257997r925978_rule'
  tag stig_id: 'RHEL-09-255105'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61662r925977_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
