control 'SV-257781' do
  title 'The graphical display manager must not be the default target on RHEL 8 unless approved.'
  desc 'Internet services that are not required for system or application processes must not be active to decrease the attack surface of the system. Graphical display managers have a long history of security vulnerabilities and must not be used, unless approved and documented.'
  desc 'check', 'Verify that the system is configured to boot to the command line:

$ systemctl get-default
multi-user.target

If the system default target is not set to "multi-user.target" and the Information System Security Officer (ISSO) lacks a documented requirement for a graphical user interface, this is a finding.'
  desc 'fix', 'Document the requirement for a graphical user interface with the ISSO or reinstall the operating system without the graphical user interface. If reinstallation is not feasible, then continue with the following procedure:

Open an SSH session and enter the following commands:

$ sudo systemctl set-default multi-user.target

A reboot is required for the changes to take effect.'
  impact 0.5
  tag check_id: 'C-55155r809376_chk'
  tag severity: 'medium'
  tag gid: 'V-251718'
  tag rid: 'SV-257781r809378_rule'
  tag stig_id: 'RHEL-08-040321'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55109r809377_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable inside the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('gui_required')
    impact 0.0
    describe 'skip' do
      skip 'A GUI is indicated as a requirement for this system. This control is Not Applicable.'
    end
  else
    get_default = command('systemctl get-default').stdout.strip

    describe get_default do
      it { should cmp 'multi-user.target' }
    end
  end
end
