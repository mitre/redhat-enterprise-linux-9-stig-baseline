control 'SV-258017' do
  title 'RHEL 9 must prevent a user from overriding the disabling of the graphical user interface autorun function.'
  desc 'Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify RHEL 9 disables ability of the user to override the graphical user interface autorun setting.

Determine which profile the system database is using with the following command:

$ gsettings writable org.gnome.desktop.media-handling autorun-never

false

If "autorun-never" is writable, the result is "true". If this is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the GNOME desktop to not allow a user to change the setting that disables autorun on removable media.

Add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock" to prevent user modification:

/org/gnome/desktop/media-handling/autorun-never

Then update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-61758r1045087_chk'
  tag severity: 'medium'
  tag gid: 'V-258017'
  tag rid: 'SV-258017r1045088_rule'
  tag stig_id: 'RHEL-09-271035'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-61682r926037_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b', 'IA-3']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  # the lockfile should not need to be examined because the writable status for a given key is directly derived from its existence in a lockfile and consequently updated dconf database

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('autorun-never', 'org.gnome.desktop.media-handling')
  gui_autorun_writable_required = input('gui_autorun_writable_required')

  unless g.has_gui?
    impact 0.0
    describe 'The system does not have a GUI/desktop environment installed; this control is Not Applicable' do
      skip 'A GUI/desktop environment is not installed; this control is Not Applicable.'
    end
  else
    if g.has_non_gnome_gui?
      skip_message_addition = ''

      if g.has_gnome_gui? && !gs.locked?
        if !gs.error? && gui_autorun_writable_required
          skip_message_addition = "Profile inputs indicate that the value of #{gs} is a documented operational requirement."
        else
          describe gs do
            it 'should be locked.' do
              expect(subject).to be_locked, "#{subject} must be set as not writable by creating/modifying the appropriate `gconf` lockfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
            end
          end
        end
      end

      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required as there is no guidance for non-GNOME desktop environments, which were identified as being installed on the system.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}#{skip_message_addition.length == 0 ? '' : "\n#{skip_message_addition}"}"
      end
    else
      if !gs.error? && !gs.locked? && gui_autorun_writable_required
        impact 0.0
        describe gs do
          skip "Profile inputs indicate that the value of #{gs} is a documented operational requirement."
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
end
