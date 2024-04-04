control 'SV-257785' do
  title 'The x86 Ctrl-Alt-Delete key sequence must be disabled on RHEL 8.'
  desc 'A locally logged-on user, who presses Ctrl-Alt-Delete when at the
console, can reboot the system. If accidentally pressed, as could happen in the
case of a mixed OS environment, this can create the risk of short-term loss of
availability of systems due to unintentional reboot. In a graphical user
environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is
reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify RHEL 8 is not configured to reboot the system when Ctrl-Alt-Delete
is pressed with the following command:

    $ sudo systemctl status ctrl-alt-del.target

    ctrl-alt-del.target
    Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
    Active: inactive (dead)

    If the "ctrl-alt-del.target" is loaded and not masked, this is a finding.'
  desc 'fix', 'Configure the system to disable the Ctrl-Alt-Delete sequence for the command line with the following commands:

$ sudo systemctl disable ctrl-alt-del.target

$ sudo systemctl mask ctrl-alt-del.target

Created symlink /etc/systemd/system/ctrl-alt-del.target -> /dev/null

Reload the daemon for this change to take effect.

$ sudo systemctl daemon-reload'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230529'
  tag rid: 'SV-257785r833338_rule'
  tag stig_id: 'RHEL-08-040170'
  tag fix_id: 'F-33173r833337_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  c = systemd_service('ctrl-alt-del.target')

  describe.one do
    describe c do
      its('params.LoadState') { should eq 'masked' }
    end
    describe c do
      its('params.LoadState') { should eq 'not-found' }
    end
  end
end
