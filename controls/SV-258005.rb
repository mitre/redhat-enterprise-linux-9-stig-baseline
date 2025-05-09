control 'SV-258005' do
  title 'RHEL 9 SSH daemon must not allow rhosts authentication.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.'
  desc 'check', %q(Verify the SSH daemon does not allow rhosts authentication with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*ignorerhosts'

IgnoreRhosts yes

If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to not allow rhosts authentication.

Add the following line to "/etc/ssh/sshd_config" or to a file in "/etc/ssh/sshd_config.d", or uncomment the line and set the value to "yes":

IgnoreRhosts yes

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61746r952205_chk'
  tag severity: 'medium'
  tag gid: 'V-258005'
  tag rid: 'SV-258005r1045069_rule'
  tag stig_id: 'RHEL-09-255145'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61670r1045068_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('IgnoreRhosts') { should cmp 'yes' }
  end
end
