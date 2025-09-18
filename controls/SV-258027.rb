control 'SV-258027' do
  title 'RHEL 9 must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'Setting the screensaver mode to blank-only conceals the contents of the display from passersby.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

To ensure the screensaver is configured to be blank, run the following command:

$ gsettings writable org.gnome.desktop.screensaver picture-uri

false

If "picture-uri" is writable and the result is "true", this is a finding.'
  desc 'fix', %q(Configure RHEL 9 to prevent a user from overriding the picture-uri setting for graphical user interfaces.

In the file "/etc/dconf/db/local.d/00-security-settings", add or update the following lines:

[org/gnome/desktop/screensaver]
picture-uri=''

Prevent user modification by adding the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock":

/org/gnome/desktop/screensaver/picture-uri

Update the dconf system databases:

$ sudo dconf update)
  impact 0.5
  tag check_id: 'C-61768r1045104_chk'
  tag severity: 'medium'
  tag gid: 'V-258027'
  tag rid: 'SV-258027r1045106_rule'
  tag stig_id: 'RHEL-09-271085'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-61692r1045105_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  # the lockfile should not need to be examined because the writable status for a given key is directly derived from its existence in a lockfile and consequently updated dconf database

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('picture-uri', 'org.gnome.desktop.screensaver')
  uri = input('screensaver_picture_uri')

  if g.has_gui?
    if g.has_non_gnome_gui?
      if g.has_gnome_gui?
        unless gs.set?(uri)
          describe gs do
            it "should be #{uri}." do
              expect(subject).to be_set(uri), "#{subject} must be set to `#{uri}` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
            end
          end
        end
        unless gs.locked?
          describe gs do
            it 'should be locked.' do
              expect(subject).to be_locked, "#{subject} must be set as not writable by creating/modifying the appropriate `gconf` lockfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
            end
          end
        end
      end

      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required as there is no guidance for non-GNOME desktop environments, which were identified as being installed on the system.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}"
      end
    else
      describe gs do
        it "should be #{uri}." do
          expect(subject).to be_set(uri), "#{subject} must be set to `#{uri}` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
        end
      end
      describe gs do
        it 'should be locked.' do
          expect(subject).to be_locked, "#{subject} must be set as not writable by creating/modifying the appropriate `gconf` lockfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
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
