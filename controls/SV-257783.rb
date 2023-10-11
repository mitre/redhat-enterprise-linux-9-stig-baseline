control 'SV-257783' do
  title 'RHEL 9 systemd-journald service must be enabled.'
  desc 'In the event of a system failure, RHEL 9 must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to system processes.'
  desc 'check', 'Verify that "systemd-journald" is active with the following command:

$ systemctl is-active systemd-journald

active

If the systemd-journald service is not active, this is a finding.'
  desc 'fix', 'To enable the systemd-journald service, run the following command:

$ sudo systemctl enable --now systemd-journald'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61524r925334_chk'
  tag severity: 'medium'
  tag gid: 'V-257783'
  tag rid: 'SV-257783r925336_rule'
  tag stig_id: 'RHEL-09-211040'
  tag gtitle: 'SRG-OS-000269-GPOS-00103'
  tag fix_id: 'F-61448r925335_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
