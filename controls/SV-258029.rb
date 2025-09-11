control 'SV-258029' do
  title 'RHEL 9 must disable the ability of a user to restart the system from the login screen.'
  desc 'A user who is at the console can reboot the system at the login screen. If restart or shutdown buttons are pressed at the login screen, this can create the risk of short-term loss of availability of systems due to reboot.'
  desc 'check', %q(Note: This requirement assumes the use of the RHEL 9 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify RHEL 9 disables a user's ability to restart the system with the following command:

$ gsettings get org.gnome.login-screen disable-restart-buttons

true

If "disable-restart-buttons" is "false", this is a finding.)
  desc 'fix', "Configure RHEL 9 to disable a user's ability to restart the system.

$ gsettings set org.gnome.login-screen disable-restart-buttons true

Update the dconf system databases:

$ sudo dconf update"
  impact 0.5
  tag check_id: 'C-61770r1045107_chk'
  tag severity: 'medium'
  tag gid: 'V-258029'
  tag rid: 'SV-258029r1045109_rule'
  tag stig_id: 'RHEL-09-271095'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61694r1045108_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  no_gui = command('ls /usr/share/xsessions/*').stderr.match?(/No such file or directory/)

  if no_gui
    impact 0.0
    describe 'The system does not have a GUI Desktop is installed; this control is Not Applicable' do
      skip 'A GUI desktop is not installed; this control is Not Applicable.'
    end
  else
    # TODO: q1: should we have a gsettings resource?  or would it fit under the dconf resource that we might create?
    # TODO: q2: do we need to add a check to see if gsettings is installed?  my brief skim did not have a requirement that says that it must be installed.  is it possible that we would have to fallback to the checking /etc/dconf/db/* approach or manual review?
    # TODO: q3: the requirement says that the ability for a user to do this thing must be disabled entirely but we are only checking the runtime status of this setting.  is it necessary to ensure that the lockfile also contains this requirement so that a user could not modify the settings between scans?  it seems like there is a 'gsettings writable' subcommand that might check this status
    # TODO: q4: it is possible for schemas like 'org.gnome.login-screen' to not be there (in my case on a GUI less system so it'll probably be there on one with a GUI).  should we add an additional check to ensure that the schema exists before looking for a particular item within it?
    restart_button_setting = command('gsettings get org.gnome.login-screen disable-restart-buttons').stdout.strip
    describe 'GUI settings should disable the restart button' do
      subject { restart_button_setting }
      it { should cmp 'true' }
    end
  end
end
