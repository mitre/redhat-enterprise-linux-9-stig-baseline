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
    describe 'The system does not have a GUI Desktop is installed, this control is Not Applicable' do
      skip 'A GUI desktop is not installed, this control is Not Applicable.'
    end
  else

    restart_button_setting = command('grep ^disable-restart-buttons /etc/dconf/db/*').stdout.strip.match(/:disable-restart-buttons=(\S+)/)[1]

    describe 'GUI settings should disable the restart button' do
      subject { restart_button_setting }
      it { should cmp 'true' }
    end
  end
end
