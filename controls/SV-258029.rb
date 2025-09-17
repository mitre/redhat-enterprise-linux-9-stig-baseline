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

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('disable-restart-buttons', 'org.gnome.login-screen')

  if g.has_gui?
    if g.has_gnome_gui?
      if g.has_non_gnome_gui?
        if !gs.exist? || !gs.set?('true')
          describe gs do
            it 'should exist.' do
              expect(subject).to exist, "#{subject} must be set using either `gsettings set` or modifying the `gconf` keyfiles and regenerating the `gconf` databases.  Received the following error on access: `#{subject.get.stderr.strip}`."
            end
            it 'should be true.' do
              expect(subject).to be_set('true'), "#{subject} must be set to `true` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases."
            end
          end
        end
        describe 'Non-GNOME desktop environments detected' do
          skip "Manual check required.  There is no guidance for non-GNOME desktop environments.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}"
        end
      else
        describe gs do
          it 'should exist.' do
            expect(subject).to exist, "#{subject} must be set using either `gsettings set` or modifying the `gconf` keyfiles and regenerating the `gconf` databases.  Received the following error on access: `#{subject.get.stderr.strip}`."
          end
          it 'should be true.' do
            expect(subject).to be_set('true'), "#{subject} must be set to `true` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases."
          end
        end
      end
    else
      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required.  There is no guidance for non-GNOME desktop environments.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_guis.join("\n\t- ")}"
      end
    end
  else
    impact 0.0
    describe 'The system does not have a GUI/desktop environment installed; this control is Not Applicable' do
      skip 'A GUI/desktop environment is not installed; this control is Not Applicable.'
    end
  end
end
