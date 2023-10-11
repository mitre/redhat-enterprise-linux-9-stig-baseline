control 'SV-257849' do
  title 'RHEL 9 file system automount function must be disabled unless required.'
  desc 'An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

'
  desc 'check', 'Verify that RHEL 9 file system automount function has been disabled with the following command:

$ sudo systemctl is-enabled  autofs

masked

If the returned value is not "masked", "disabled", "Failed to get unit file state for autofs.service for autofs", or "enabled", and is not documented as operational requirement with the information system security officer ISSO, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disable the ability to automount devices.

The autofs service can be disabled with the following command:

$ sudo systemctl mask --now autofs.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61590r925532_chk'
  tag severity: 'medium'
  tag gid: 'V-257849'
  tag rid: 'SV-257849r925534_rule'
  tag stig_id: 'RHEL-09-231040'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-61514r925533_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b', 'IA-3', 'IA-3']
end
