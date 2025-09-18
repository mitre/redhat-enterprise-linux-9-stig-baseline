control 'SV-258031' do
  title 'RHEL 9 must disable the ability of a user to accidentally press Ctrl-Alt-Del and cause a system to shut down or reboot.'
  desc 'A locally logged-in user who presses Ctrl-Alt-Del, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot.'
  desc 'check', %q(Verify RHEL 9 is configured to ignore the Ctrl-Alt-Del sequence in the GNOME desktop with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.settings-daemon.plugins.media-keys logout

"['']"

If the GNOME desktop is configured to shut down when Ctrl-Alt-Del is pressed, this is a finding.)
  desc 'fix', %q(Configure RHEL 9 to ignore the Ctrl-Alt-Del sequence in the GNOME desktop.

Run the following command to set the media-keys logout setting:

$ gsettings set org.gnome.settings-daemon.plugins.media-keys logout "['']"

Run the following command to update the database:

$ sudo dconf update)
  impact 0.5
  tag check_id: 'C-61772r926078_chk'
  tag severity: 'medium'
  tag gid: 'V-258031'
  tag rid: 'SV-258031r1045114_rule'
  tag stig_id: 'RHEL-09-271105'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61696r1045113_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('logout', 'org.gnome.settings-daemon.plugins.media-keys')

  if g.has_gui?
    if g.has_non_gnome_gui?
      if g.has_gnome_gui? && !gs.set?("['']")
        describe gs do
          it "should be `['']`." do
            expect(subject).to be_set("['']"), "#{subject} must be set to `['']` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
          end
        end
      end

      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required as there is no guidance for non-GNOME desktop environments, which were identified as being installed on the system.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}"
      end
    else
      describe gs do
        it "should be `['']`." do
          expect(subject).to be_set("['']"), "#{subject} must be set to `['']` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
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
