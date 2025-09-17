control 'SV-258014' do
  title 'RHEL 9 must disable the graphical user interface automount function unless required.'
  desc 'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify RHEL 9 disables the graphical user interface automount function with the following command:

$ gsettings get org.gnome.desktop.media-handling automount-open

false

If "automount-open" is set to "true", and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the GNOME desktop to disable automated mounting of removable media.

The dconf settings can be edited in the /etc/dconf/db/* location.

Update the [org/gnome/desktop/media-handling] section of the "/etc/dconf/db/local.d/00-security-settings" database file and add or update the following lines:

[org/gnome/desktop/media-handling]
automount-open=false

Then update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  tag check_id: 'C-61755r1045083_chk'
  tag severity: 'medium'
  tag gid: 'V-258014'
  tag rid: 'SV-258014r1045084_rule'
  tag stig_id: 'RHEL-09-271020'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-61679r926028_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b', 'IA-3']
tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('automount-open', 'org.gnome.desktop.media-handling')
  gui_automount_required = input('gui_automount_required')

  unless g.has_gui?
    impact 0.0
    describe 'The system does not have a GUI/desktop environment installed; this control is Not Applicable' do
      skip 'A GUI/desktop environment is not installed; this control is Not Applicable.'
    end
  else
    if g.has_non_gnome_gui?
      skip_message_addition = ''

      if g.has_gnome_gui? && !gs.set('false')
        if !gs.error? && gui_automount_required
          skip_message_addition = "Profile inputs indicate that the value of #{gs} is a documented operational requirement."
        else
          describe gs do
            it 'should be false.' do
              expect(subject).to be_set('false'), "#{subject} must be set to `false` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Receieved the following error on access: `#{subject.error}`." : ''}"
            end
          end
        end
      end

      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required as there is no guidance for non-GNOME desktop environments, which were identified as being installed on the system.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}#{skip_message_addition.length == 0 ? '' : "\n#{skip_message_addition}"}"
      end
    else
      if !gs.error? && !gs.set('false') && gui_automount_required
        impact 0.0
      end
      describe gs do
        it 'should be false.' do
          expect(subject).to be_set('false'), !gs.error? && gui_automount_required ? "Profile inputs indicate that the value of #{gs} is a documented operational requirement." : "#{subject} must be set to `false` using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Receieved the following error on access: `#{subject.error}`." : ''}"
        end
      end
    end
  end
end
