control 'SV-257999' do
  title 'RHEL 9 SSH server configuration file must have mode 0600 or less permissive.'
  desc 'Service configuration files enable or disable features of their respective services that if configured incorrectly can lead to insecure and vulnerable configurations. Therefore, service configuration files should be owned by the correct group to prevent unauthorized changes.'
  desc 'check', 'Verify the permissions of the "/etc/ssh/sshd_config" file with the following command:

$ ls -al /etc/ssh/sshd_config

rw-------. 1 root root 3669 Feb 22 11:34 /etc/ssh/sshd_config

If the "/etc/ssh/sshd_config" permissions are not "0600", this is a finding.'
  desc 'fix', 'Configure the "/etc/ssh/sshd_config" permissions to be "0600" with the following command:

$ sudo chmod 0600 /etc/ssh/sshd_config'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61740r925982_chk'
  tag severity: 'medium'
  tag gid: 'V-257999'
  tag rid: 'SV-257999r925984_rule'
  tag stig_id: 'RHEL-09-255115'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61664r925983_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
