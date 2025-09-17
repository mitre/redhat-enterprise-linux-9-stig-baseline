control 'SV-258016' do
  title 'RHEL 9 must disable the graphical user interface autorun function unless required.'
  desc 'Allowing autorun commands to execute may introduce malicious code to a system. Configuring this setting prevents autorun commands from executing.'
  desc 'check', 'Verify RHEL 9 disables the graphical user interface autorun function with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.desktop.media-handling autorun-never

true

If "autorun-never" is set to "false", and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the GNOME desktop to disable the autorun function on removable media.

The dconf settings can be edited in the /etc/dconf/db/* location.

Update the [org/gnome/desktop/media-handling] section of the "/etc/dconf/db/local.d/00-security-settings" database file and add or update the following lines:

[org/gnome/desktop/media-handling]
autorun-never=true

Then update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-61757r926033_chk'
  tag severity: 'medium'
  tag gid: 'V-258016'
  tag rid: 'SV-258016r958804_rule'
  tag stig_id: 'RHEL-09-271030'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61681r926034_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('autorun-never', 'org.gnome.desktop.media-handling')

  if g.has_gui?
    if input('gui_autorun_required')
      impact 0.0
      describe 'N/A' do
        skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
      end
    else
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
    end
  else
    impact 0.0
    describe 'The system does not have a GUI/desktop environment installed; this control is Not Applicable' do
      skip 'A GUI/desktop environment is not installed; this control is Not Applicable.'
    end
  end
end
