control 'SV-258030' do
  title 'RHEL 9 must prevent a user from overriding the disable-restart-buttons setting for the graphical user interface.'
  desc 'A user who is at the console can reboot the system at the login screen. If restart or shutdown buttons are pressed at the login screen, this can create the risk of short-term loss of availability of systems due to reboot.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify RHEL 9 prevents a user from overriding the disable-restart-buttons setting for graphical user interfaces. 

$ gsettings writable org.gnome.login-screen disable-restart-buttons
 
false
 
If "disable-restart-buttons" is writable and the result is "true", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent a user from overriding the disable-restart-buttons setting for graphical user interfaces. 

Create a database to contain the systemwide graphical user logon settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/locks/session

Add the following line to prevent nonprivileged users from modifying it:

/org/gnome/login-screen/disable-restart-buttons

Run the following command to update the database:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-61771r1045110_chk'
  tag severity: 'medium'
  tag gid: 'V-258030'
  tag rid: 'SV-258030r1045112_rule'
  tag stig_id: 'RHEL-09-271100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61695r1045111_fix'
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
    restart_button_setting = command('gsettings writable org.gnome.login-screen disable-restart-buttons').stdout.strip
    describe 'GUI restart button override must be disabled' do
      subject { restart_button_setting }
      it { should cmp 'false' }
    end
  end
end
