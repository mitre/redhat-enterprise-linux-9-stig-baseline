control 'SV-257849' do
  title 'RHEL 9 file system automount function must be disabled unless required.'
  desc 'An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.'
  desc 'check', 'Note: If the autofs service is not installed, this requirement is Not Applicable.

Verify that the RHEL 9 file system automount function has been disabled with the following command:

$ systemctl is-enabled  autofs

masked

If the returned value is not "masked", "disabled", or "Failed to get unit file state for autofs.service for autofs" and is not documented as an operational requirement with the information system security officer (ISSO), this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disable the ability to automount devices.

The autofs service can be disabled with the following command:

$ sudo systemctl mask --now autofs.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag gid: 'V-257849'
  tag rid: 'SV-257849r1044928_rule'
  tag stig_id: 'RHEL-09-231040'
  tag fix_id: 'F-61514r925533_fix'
  tag cci: ['CCI-000778', 'CCI-000366', 'CCI-001958']
  tag nist: ['IA-3', 'CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('autofs_required') == true
    describe systemd_service('autofs.service') do
      it { should be_running }
      it { should be_enabled }
      it { should be_installed }
    end
  elsif package('autofs').installed?
    describe systemd_service('autofs.service') do
      it { should_not be_running }
      it { should_not be_enabled }
      it { should_not be_installed }
    end
  else
    impact 0.0
    describe 'The autofs service is not installed' do
      skip 'The autofs service is not installed, this control is Not Applicable.'
    end
  end
end
