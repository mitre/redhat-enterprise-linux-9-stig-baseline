control 'SV-257993' do
  title 'RHEL 9 must not allow users to override SSH environment variables.'
  desc 'SSH environment options potentially allow users to bypass access
restriction in some configurations.'
  desc 'check', 'Verify that unattended or automatic logon via SSH is disabled with the following command:

$ sudo grep -ir permituserenvironment /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*

PermitUserEnvironment no

If "PermitUserEnvironment" is set to "yes", is missing completely, or is commented out, this is a finding.

If the required value is not set, this is a finding.'
  desc 'fix', 'Configure the RHEL 9 SSH daemon to not allow unattended or automatic logon to the system.

Add or edit the following line in the "/etc/ssh/sshd_config" file:

PermitUserEnvironment no

Restart the SSH daemon  for the setting to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag gid: 'V-257993'
  tag rid: 'SV-257993r943042_rule'
  tag stig_id: 'RHEL-09-255085'
  tag fix_id: 'F-61658r925965_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This requirement is Not Applicable inside a container, the containers host manages the containers filesystems') {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  describe sshd_config do
    its('PermitUserEnvironment') { should eq 'no' }
  end
end
