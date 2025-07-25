control 'SV-257992' do
  title 'RHEL 9 must not allow a noncertificate trusted host SSH logon to the system.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.'
  desc 'check', %q(Verify the operating system does not allow a noncertificate trusted host SSH logon to the system with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*hostbasedauthentication'

HostbasedAuthentication no

If the "HostbasedAuthentication" keyword is not set to "no", is missing, or is commented out, this is a finding.

If the required value is not set, this is a finding.)
  desc 'fix', 'To configure RHEL 9 to not allow a noncertificate trusted host SSH logon to the system, add or modify the following line in "/etc/ssh/sshd_config" or in a file in "/etc/ssh/sshd_config.d".

HostbasedAuthentication no

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-61733r952189_chk'
  tag severity: 'medium'
  tag gid: 'V-257992'
  tag rid: 'SV-257992r1045047_rule'
  tag stig_id: 'RHEL-09-255080'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-61657r1045046_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('HostBasedAuthentication') { should cmp 'no' }
  end
end
