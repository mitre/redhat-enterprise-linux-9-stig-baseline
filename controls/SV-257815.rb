control 'SV-257815' do
  title 'RHEL 9 must disable acquiring, saving, and processing core dumps.'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.'
  desc 'check', 'Verify RHEL 9 is not configured to acquire, save, or process core dumps with the following command:

$ sudo systemctl status systemd-coredump.socket

systemd-coredump.socket
Loaded: masked (Reason: Unit systemd-coredump.socket is masked.)
Active: inactive (dead)

If the "systemd-coredump.socket" is loaded and not masked and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the system to disable the systemd-coredump.socket with the following command:

$ sudo systemctl mask --now systemd-coredump.socket

Created symlink /etc/systemd/system/systemd-coredump.socket -> /dev/null

Reload the daemon for this change to take effect.

$ sudo systemctl daemon-reload'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257815'
  tag rid: 'SV-257815r991589_rule'
  tag stig_id: 'RHEL-09-213100'
  tag fix_id: 'F-61480r925431_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  s = systemd_service('systemd-coredump.socket')

  describe.one do
    describe s do
      its('params.LoadState') { should eq 'masked' }
    end
    describe s do
      its('params.LoadState') { should eq 'not-found' }
    end
  end
end
