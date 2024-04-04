control 'SV-257786' do
  title 'The debug-shell systemd service must be disabled on RHEL 8.'
  desc 'The debug-shell requires no authentication and provides root
privileges to anyone who has physical access to the machine.  While this
feature is disabled by default, masking it adds an additional layer of
assurance that it will not be enabled via a dependency in systemd.  This also
prevents attackers with physical access from trivially bypassing security on
the machine through valid troubleshooting configurations and gaining root
access when the system is rebooted.'
  desc 'check', 'Verify RHEL 8 is configured to mask the debug-shell systemd service with
the following command:

    $ sudo systemctl status debug-shell.service

    debug-shell.service
    Loaded: masked (Reason: Unit debug-shell.service is masked.)
    Active: inactive (dead)

    If the "debug-shell.service" is loaded and not masked, this is a finding.'
  desc 'fix', 'Configure the system to mask the debug-shell systemd service with the
following command:

    $ sudo systemctl mask debug-shell.service

    Created symlink /etc/systemd/system/debug-shell.service -> /dev/null

    Reload the daemon to take effect.

    $ sudo systemctl daemon-reload'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230532'
  tag rid: 'SV-257786r627750_rule'
  tag stig_id: 'RHEL-08-040180'
  tag fix_id: 'F-33176r619892_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
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
