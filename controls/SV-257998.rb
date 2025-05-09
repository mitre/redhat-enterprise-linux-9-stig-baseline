control 'SV-257998' do
  title 'The RHEL 9 SSH server configuration file must be owned by root.'
  desc 'Service configuration files enable or disable features of their respective services, which if configured incorrectly, can lead to insecure and vulnerable configurations. Therefore, service configuration files must be owned by the correct group to prevent unauthorized changes.'
  desc 'check', 'Verify the ownership of the "/etc/ssh/sshd_config" file and the contents of "/etc/ssh/sshd_config.d" with the following command:

$ sudo find /etc/ssh/sshd_config /etc/ssh/sshd_config.d -exec stat -c "%U %n" {} \\;

root /etc/ssh/sshd_config
root /etc/ssh/sshd_config.d
root /etc/ssh/sshd_config.d/50-cloud-init.conf
root /etc/ssh/sshd_config.d/50-redhat.conf

If the "/etc/ssh/sshd_config" file or "/etc/ssh/sshd_config.d" or any files in the "sshd_config.d" directory do not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure  the "/etc/ssh/sshd_config" file and the contents of "/etc/ssh/sshd_config.d" to be owned by root with the following command:

$ sudo chown -R root /etc/ssh/sshd_config /etc/ssh/sshd_config.d'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61739r1082179_chk'
  tag severity: 'medium'
  tag gid: 'V-257998'
  tag rid: 'SV-257998r1082181_rule'
  tag stig_id: 'RHEL-09-255110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61663r1082180_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe file('/etc/ssh/sshd_config') do
    it { should exist }
    it { should be_owned_by 'root' }
  end
end
