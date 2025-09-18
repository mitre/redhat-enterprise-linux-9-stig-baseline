control 'SV-258033' do
  title 'RHEL 9 must disable the user list at logon for graphical user interfaces.'
  desc 'Leaving the user list enabled is a security risk since it allows
anyone with physical access to the system to enumerate known user accounts
without authenticated access to the system.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify that RHEL 9 disables the user logon list for graphical user interfaces with the following command:

$ gsettings get org.gnome.login-screen disable-user-list

true

If the setting is "false", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disable the user list at logon for graphical user interfaces.

Create a database to contain the systemwide screensaver settings (if it does not already exist) with the following command:
Note: The example below is using the database "local" for the system. If the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

$ sudo touch /etc/dconf/db/local.d/02-login-screen

[org/gnome/login-screen]
disable-user-list=true

Update the system databases:

$ sudo dconf update'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258033'
  tag rid: 'SV-258033r1045120_rule'
  tag stig_id: 'RHEL-09-271115'
  tag fix_id: 'F-61698r1045119_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('disable-user-list', 'org.gnome.login-screen')

  unless g.has_gui?
    impact 0.0
    describe 'The system does not have a GUI/desktop environment installed; this control is Not Applicable' do
      skip 'A GUI/desktop environment is not installed; this control is Not Applicable.'
    end
  else
    if g.has_non_gnome_gui?
      if g.has_gnome_gui? && !gs.set?('true')
        describe gs do
          it 'should be true.' do
            expect(subject).to be_set('true'), "#{subject} must be set to `true` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
          end
        end
      end

      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required as there is no guidance for non-GNOME desktop environments, which were identified as being installed on the system.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}"
      end
    else
      describe gs do
        it 'should be true.' do
          expect(subject).to be_set('true'), "#{subject} must be set to `true` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
        end
      end
    end
  end
end
