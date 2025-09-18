control 'SV-258025' do
  title 'RHEL 9 must initiate a session lock for graphical user interfaces when the screensaver is activated.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to logout because of the temporary nature of the absence.'
  desc 'check', 'Verify RHEL 9 initiates a session lock for graphical user interfaces when the screensaver is activated with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.desktop.screensaver lock-delay

uint32 5

If the "uint32" setting is not set to "5" or less, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to initiate a session lock for graphical user interfaces when a screensaver is activated.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:

Note: The example below is using the database "local" for the system, so if the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

$ sudo touch /etc/dconf/db/local.d/00-screensaver

[org/gnome/desktop/screensaver]
lock-delay=uint32 5

The "uint32" must be included along with the integer key values as shown.

Update the system databases:

$ sudo dconf update'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-258025'
  tag rid: 'SV-258025r958402_rule'
  tag stig_id: 'RHEL-09-271075'
  tag fix_id: 'F-61690r926061_fix'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('lock-delay', 'org.gnome.desktop.screensaver')
  delay = input('screensaver_lock_delay')
  set_check = proc { |val|
    numeric_type, value = val.split(' ')
    value = value.to_i
    numeric_type == 'uint32' && value >= 0 && value <= delay
  }

  if g.has_gui?
    if g.has_non_gnome_gui?
      if g.has_gnome_gui? && !gs.set?(&set_check)
        describe gs do
          it "should be greater than or equal to 0 and less than or equal to #{delay}." do
            expect(subject).to be_set(&set_check), "#{subject} must be set to `uint32` and then an integer greater than or equal to 0 and less than or equal to #{delay} using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
          end
        end
      end

      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required as there is no guidance for non-GNOME desktop environments, which were identified as being installed on the system.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}"
      end
    else
      describe gs do
        it "should be greater than or equal to 0 and less than or equal to #{delay}." do
          expect(subject).to be_set(&set_check), "#{subject} must be set to `uint32` and then an integer greater than or equal to 0 and less than or equal to #{delay} using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
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
