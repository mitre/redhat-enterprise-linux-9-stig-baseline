control 'SV-257985' do
  title 'RHEL 9 must not permit direct logons to the root account using remote access via SSH.'
  desc "Even though the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging directly on as root. In addition, logging in with a user-specific account provides individual accountability of actions performed on the system and also helps to minimize direct attack attempts on root's password."
  desc 'check', 'Verify RHEL 9 remote access using SSH prevents users from logging on directly as "root" with the following command:

$ sudo grep -ir PermitRootLogin /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*

PermitRootLogin no

If the "PermitRootLogin" keyword is set to "yes", is missing, or is commented out, this is a finding.'
  desc 'fix', 'To configure the system to prevent SSH users from logging on directly as root add or modify the following line in "/etc/ssh/sshd_config".

 PermitRootLogin no

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag gid: 'V-257985'
  tag rid: 'SV-257985r943036_rule'
  tag stig_id: 'RHEL-09-255045'
  tag fix_id: 'F-61650r925941_fix'
  tag cci: ['CCI-000770', 'CCI-000366']
  tag nist: ['IA-2 (5)', 'CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('PermitRootLogin') { should cmp input('permit_root_login') }
  end
end
