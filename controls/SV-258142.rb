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
  tag check_id: 'C-61883r926411_chk'
  tag severity: 'medium'
  tag gid: 'V-258142'
  tag rid: 'SV-258142r926413_rule'
  tag stig_id: 'RHEL-09-652020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61807r926412_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
