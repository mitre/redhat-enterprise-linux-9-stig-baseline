control 'SV-257999' do
  title "RHEL 9 SSH server configuration files' permissions must not be modified."
  desc 'Service configuration files enable or disable features of their respective services, that if configured incorrectly, can lead to insecure and vulnerable configurations. Therefore, service configuration files must have correct permissions (owner, group owner, mode) to prevent unauthorized changes.'
  desc 'check', 'Verify the permissions of the "/etc/ssh/sshd_config" file with the following command:

$ sudo rpm --verify openssh-server

If the command returns any output, this is a finding.'
  desc 'fix', 'Run the following commands to restore the correct permissions of OpenSSH server configuration files:

$ sudo dnf reinstall -y openssh-server
$ rpm --setugids openssh-server
$ rpm --setperms openssh-server'
  impact 0.5
  tag check_id: 'C-61740r1069357_chk'
  tag severity: 'medium'
  tag gid: 'V-257999'
  tag rid: 'SV-257999r1082182_rule'
  tag stig_id: 'RHEL-09-255115'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61664r1069358_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  system_file = '/etc/ssh/sshd_config'

  mode = input('expected_modes')[system_file]

  describe file(system_file) do
    it { should exist }
    it { should_not be_more_permissive_than(mode) }
  end
end
