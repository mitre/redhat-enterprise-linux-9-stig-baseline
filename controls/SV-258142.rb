control 'SV-258142' do
  title 'The rsyslog service on RHEL 9 must be active.'
  desc 'The "rsyslog" service must be running to provide logging services, which are essential to system administration.'
  desc 'check', 'Verify that "rsyslog" is active with the following command:

$ systemctl is-active rsyslog

active

If the rsyslog service is not active, this is a finding.'
  desc 'fix', 'To enable the rsyslog service, run the following command:

$ sudo systemctl enable --now rsyslog'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258142'
  tag rid: 'SV-258142r991589_rule'
  tag stig_id: 'RHEL-09-652020'
  tag fix_id: 'F-61807r926412_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end
