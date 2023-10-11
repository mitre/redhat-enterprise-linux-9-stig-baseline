control 'SV-258001' do
  title 'RHEL 9 SSH public host key files must have mode 0644 or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'check', 'Verify the SSH public host key files have a mode of "0644" or less permissive with the following command:

Note: SSH public key files may be found in other directories on the system depending on the installation.

$ sudo stat -c "%a %n" /etc/ssh/*.pub

644 /etc/ssh/ssh_host_dsa_key.pub
644 /etc/ssh/ssh_host_ecdsa_key.pub
644 /etc/ssh/ssh_host_ed25519_key.pub
644 /etc/ssh/ssh_host_rsa_key.pub

If any key.pub file has a mode more permissive than "0644", this is a finding.'
  desc 'fix', 'Change the mode of public host key files under "/etc/ssh" to "0644" with the following command:

$ sudo chmod 0644 /etc/ssh/*key.pub

Restart the SSH daemon for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61742r925988_chk'
  tag severity: 'medium'
  tag gid: 'V-258001'
  tag rid: 'SV-258001r925990_rule'
  tag stig_id: 'RHEL-09-255125'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61666r925989_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
