control 'SV-257786' do
  title 'RHEL 9 debug-shell systemd service must be disabled.'
  desc 'The debug-shell requires no authentication and provides root
privileges to anyone who has physical access to the machine.  While this
feature is disabled by default, masking it adds an additional layer of
assurance that it will not be enabled via a dependency in systemd.  This also
prevents attackers with physical access from trivially bypassing security on
the machine through valid troubleshooting configurations and gaining root
access when the system is rebooted.'
  desc 'check', 'Verify RHEL 9 is configured to mask the debug-shell systemd service with the following command:

$ sudo systemctl status debug-shell.service

debug-shell.service
Loaded: masked (Reason: Unit debug-shell.service is masked.)
Active: inactive (dead)

If the "debug-shell.service" is loaded and not masked, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to mask the debug-shell systemd service with the following command:

$ sudo systemctl disable --now debug-shell.service
$ sudo systemctl mask --now debug-shell.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag gid: 'V-257786'
  tag rid: 'SV-257786r943026_rule'
  tag stig_id: 'RHEL-09-211055'
  tag fix_id: 'F-61451r943025_fix'
  tag cci: ['CCI-000366', 'CCI-002235']
  tag nist: ['CM-6 b', 'AC-6 (10)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  d = systemd_service('debug-shell.service')

  describe.one do
    describe d do
      its('params.LoadState') { should eq 'masked' }
    end
    describe d do
      its('params.LoadState') { should eq 'not-found' }
    end
  end
end
