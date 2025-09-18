control 'SV-258021' do
  title 'RHEL 9 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions.'
  desc 'A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined.

    Regardless of where the session lock is determined and implemented, once
invoked, the session lock must remain in place until the user reauthenticates.
No other activity aside from reauthentication must unlock the system.'
  desc 'check', %q(Verify RHEL 9 enables a user's session lock until that user re-establishes access using established identification and authentication procedures with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.desktop.screensaver lock-enabled

true

If the setting is "false", this is a finding.)
  desc 'fix', %q(Configure RHEL 9 to enable a user's session lock until that user re-establishes access using established identification and authentication procedures.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following example:

$ sudo vi /etc/dconf/db/local.d/00-screensaver

Edit the "[org/gnome/desktop/screensaver]" section of the database file and add or update the following lines:

# Set this to true to lock the screen when the screensaver activates
lock-enabled=true

Update the system databases:

$ sudo dconf update)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag gid: 'V-258021'
  tag rid: 'SV-258021r1015088_rule'
  tag stig_id: 'RHEL-09-271055'
  tag fix_id: 'F-61686r926049_fix'
  tag cci: ['CCI-000056', 'CCI-000058', 'CCI-000057']
  tag nist: ['AC-11 b', 'AC-11 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('lock-enabled', 'org.gnome.desktop.screensaver')

  if g.has_gui?
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
  else
    impact 0.0
    describe 'The system does not have a GUI/desktop environment installed; this control is Not Applicable' do
      skip 'A GUI/desktop environment is not installed; this control is Not Applicable.'
    end
  end
end
