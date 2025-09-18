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

  # the lockfile should not need to be examined because the writable status for a given key is directly derived from its existence in a lockfile and consequently updated dconf database

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('disable-restart-buttons', 'org.gnome.login-screen')

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
