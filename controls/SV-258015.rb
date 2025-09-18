control 'SV-258015' do
  title 'RHEL 9 must prevent a user from overriding the disabling of the graphical user interface automount function.'
  desc 'A nonprivileged account is any operating system account with authorizations of a nonprivileged user.'
  desc 'check', %q(Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify RHEL 9 disables the ability of the user to override the graphical user interface automount setting.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user

system-db:local

Check that the automount setting is locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ grep 'automount-open' /etc/dconf/db/local.d/locks/*

/org/gnome/desktop/media-handling/automount-open

If the command does not return at least the example result, this is a finding.)
  desc 'fix', 'Configure the GNOME desktop to not allow a user to change the setting that disables automated mounting of removable media.

Add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock" to prevent user modification:

/org/gnome/desktop/media-handling/automount-open

Then update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-61756r1045085_chk'
  tag severity: 'medium'
  tag gid: 'V-258015'
  tag rid: 'SV-258015r1045086_rule'
  tag stig_id: 'RHEL-09-271025'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-61680r926031_fix'
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
  gs = gsettings('automount-open', 'org.gnome.desktop.media-handling')

  if g.has_gui?
    if g.has_non_gnome_gui?
      if g.has_gnome_gui? && !gs.locked?
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
  else
    impact 0.0
    describe 'The system does not have a GUI/desktop environment installed; this control is Not Applicable' do
      skip 'A GUI/desktop environment is not installed; this control is Not Applicable.'
    end
  end
end
