control 'SV-258033' do
  title 'RHEL 9 must disable the user list at logon for graphical user interfaces.'
  desc 'Leaving the user list enabled is a security risk since it allows
anyone with physical access to the system to enumerate known user accounts
without authenticated access to the system.'
  desc 'check', 'Verify that RHEL 9 disables the user logon list for graphical user interfaces with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ sudo gsettings get org.gnome.login-screen disable-user-list
true

If the setting is "false", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disable the user list at logon for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:
Note: The example below is using the database "local" for the system, so if the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

$ sudo touch /etc/dconf/db/local.d/02-login-screen

[org/gnome/login-screen]
disable-user-list=true

Update the system databases:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258033'
  tag rid: 'SV-258033r991589_rule'
  tag stig_id: 'RHEL-09-271115'
  tag fix_id: 'F-61698r926085_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  no_gui = command('ls /usr/share/xsessions/*').stderr.match?(/No such file or directory/)

  if no_gui
    impact 0.0
    describe 'The system does not have a GUI installed, this requirement is Not Applicable.' do
      skip 'A GUI desktop is not installed, this control is Not Applicable.'
    end
  else
    describe command('gsettings get org.gnome.login-screen disable-user-list') do
      its('stdout.strip') { should cmp 'true' }
    end
  end
end
