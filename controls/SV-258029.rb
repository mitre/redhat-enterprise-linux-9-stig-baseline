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
    # TODO: q2: do we need to add a check to see if gsettings is installed?  my brief skim did not have a requirement that says that it must be installed.  is it possible that we would have to fallback to the checking /etc/dconf/db/* approach or manual review?
    # if a gnome gui is installed, gsettings is installed.  we will need to do checks for non-gnome guis
    describe gsettings('disable-restart-buttons', 'org.gnome.login-screen') do
      it 'should exist.' do
        expect(subject).to exist, "#{subject} must be set using either `gsettings set` or modifying the `gconf` keyfiles and regenerating the `gconf` databases.  Received the following error on access: `#{subject.get.stderr.strip}`."
      end
      it 'should be true.' do
        expect(subject).to be_set('true'), "#{subject} must be set to `true` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases."
      end
      it 'should be locked.' do
        expect(subject).to be_locked, "#{subject} must be set as not writable by creating/modifying the appropriate `gconf` lockfile and regenerating the `gconf` databases."
      end
    end

    restart_button_setting = command('gsettings get org.gnome.login-screen disable-restart-buttons').stdout.strip
    describe 'GUI settings should disable the restart button' do
      subject { restart_button_setting }
      it { should cmp 'true' }
    end
  end
end
