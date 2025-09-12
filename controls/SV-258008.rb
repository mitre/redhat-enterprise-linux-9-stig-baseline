control 'SV-258008' do
  title 'RHEL 9 SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', %q(Verify the SSH daemon performs strict mode checking of home directory configuration files with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*strictmodes'

StrictModes yes

If the "StrictModes" keyword is set to "no", the returned line is commented out, or no output is returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to perform strict mode checking of home directory configuration files.

Add the following line to "/etc/ssh/sshd_config" or to a file in "/etc/ssh/sshd_config.d", or uncomment the line and set the value to "yes":

StrictModes yes

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258008'
  tag rid: 'SV-258008r1045075_rule'
  tag stig_id: 'RHEL-09-255160'
  tag fix_id: 'F-61673r1045074_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('StrictModes') { should cmp 'yes' }
  end
end
