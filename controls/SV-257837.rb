control 'SV-257837' do
  title 'A graphical display manager must not be installed on RHEL 9 unless approved.'
  desc 'Unnecessary service packages must not be installed to decrease the attack surface of the system. Graphical display managers have a long history of security vulnerabilities and must not be used, unless approved and documented.'
  desc 'check', 'Verify that a graphical user interface is not installed with the following command:

$ sudo dnf list --installed "xorg*common"

Error: No matching Packages to list

If the "x11-server-common" package is installed, and the use of a graphical user interface has not been documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Document the requirement for a graphical user interface with the ISSO or remove all xorg packages with the following command:

Warning: If you are accessing the system through the graphical user interface, change to the multi-user.target with the following command:

$ sudo systemctl isolate multi-user.target

Warning: Removal of the graphical user interface will immediately render it useless. The following commands must not be run from a virtual terminal emulator in the graphical interface.

$ sudo dnf remove "xorg*"
$ sudo systemctl set-default multi-user.target'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257837'
  tag rid: 'SV-257837r925498_rule'
  tag stig_id: 'RHEL-09-215070'
  tag fix_id: 'F-61502r925497_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  input('remove_xorg_x11_server_packages').each do |p|
    describe package(p) do
      it { should_not be_installed }
    end
  end
end
