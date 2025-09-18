control 'SV-258032' do
  title 'RHEL 9 must prevent a user from overriding the Ctrl-Alt-Del sequence settings for the graphical user interface.'
  desc 'A locally logged-in user who presses Ctrl-Alt-Del, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify that users cannot enable the Ctrl-Alt-Del sequence in the GNOME desktop with the following command:

$ gsettings writable org.gnome.settings-daemon.plugins.media-keys logout

false

If "logout" is writable and the result is "true", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disallow the user changing the Ctrl-Alt-Del sequence in the GNOME desktop.

Create a database to contain the systemwide graphical user logon settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/locks/session

Add the following line to the session locks file to prevent nonprivileged users from modifying the Ctrl-Alt-Del setting:

/org/gnome/settings-daemon/plugins/media-keys/logout

Run the following command to update the database:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-61773r1045115_chk'
  tag severity: 'medium'
  tag gid: 'V-258032'
  tag rid: 'SV-258032r1045117_rule'
  tag stig_id: 'RHEL-09-271110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61697r1045116_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  # the lockfile should not need to be examined because the writable status for a given key is directly derived from its existence in a lockfile and consequently updated dconf database

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('logout', 'org.gnome.settings-daemon.plugins.media-keys')

  unless g.has_gui?
    impact 0.0
    describe 'The system does not have a GUI/desktop environment installed; this control is Not Applicable' do
      skip 'A GUI/desktop environment is not installed; this control is Not Applicable.'
    end
  else
    if g.has_non_gnome_gui?
      if g.has_gnome_gui? && !gs.locked?()
        describe gs do
          it 'should be locked.' do
            expect(subject).to be_locked, "#{subject} must be set as not writable by creating/modifying the appropriate `gconf` lockfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
          end
        end
      end

      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required as there is no guidance for non-GNOME desktop environments, which were identified as being installed on the system.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}"
      end
    else
      describe gs do
        it 'should be locked.' do
          expect(subject).to be_locked, "#{subject} must be set as not writable by creating/modifying the appropriate `gconf` lockfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
        end
      end
    end
  end
end
