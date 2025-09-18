control 'SV-258023' do
  title 'RHEL 9 must automatically lock graphical user sessions after 15 minutes of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not logout because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, the GNOME desktop can be configured to identify when a user's session has idled and take action to initiate a session lock."
  desc 'check', 'Verify RHEL 9 initiates a session lock after a 15-minute period of inactivity for graphical user interfaces with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ sudo gsettings get org.gnome.desktop.session idle-delay

uint32 900

If "idle-delay" is set to "0" or a value greater than "900", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/00-screensaver

Edit /etc/dconf/db/local.d/00-screensaver and add or update the following lines:

[org/gnome/desktop/session]
# Set the lock time out to 900 seconds before the session is considered idle
idle-delay=uint32 900

Update the system databases:

$ sudo dconf update'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012']
  tag gid: 'V-258023'
  tag rid: 'SV-258023r958402_rule'
  tag stig_id: 'RHEL-09-271065'
  tag fix_id: 'F-61688r926055_fix'
  tag cci: ['CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 a', 'AC-11 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  g = guis(input('possibly_installed_guis'))
  gs = gsettings('idle-delay', 'org.gnome.desktop.session')
  timeout = input('graphical_user_session_inactivity_timeout')
  set_check = Proc.new { |val|
    numeric_type, value = val.split(' ')
    value = value.to_i
    numeric_type == 'uint32' && value > 0 && value <= timeout
  }

  unless g.has_gui?
    impact 0.0
    describe 'The system does not have a GUI/desktop environment installed; this control is Not Applicable' do
      skip 'A GUI/desktop environment is not installed; this control is Not Applicable.'
    end
  else
    if g.has_non_gnome_gui?
      if g.has_gnome_gui? && !gs.set?(&set_check)
        describe gs do
          it "should be greater than 0 and less than or equal to #{timeout}." do
            expect(subject).to be_set(&set_check), "#{subject} must be set to `uint32` and then an integer greater than 0 and less than or equal to #{timeout} using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
          end
        end
      end

      describe 'Non-GNOME desktop environments detected' do
        skip "Manual check required as there is no guidance for non-GNOME desktop environments, which were identified as being installed on the system.  Investigate the following, possibly related packages to determine which desktop environments are installed and then determine a method to ensure that each of those desktop environments' configuration is up-to-date and matches policy:\n\t- #{g.installed_non_gnome_guis.join("\n\t- ")}"
      end
    else
      describe gs do
        it "should be greater than 0 and less than or equal to #{timeout}." do
          expect(subject).to be_set(&set_check), "#{subject} must be set to `uint32` and then an integer greater than 0 and less than or equal to #{timeout} using either `gsettings set` or by creating/modifying the appropriate `gconf` keyfile and regenerating the `gconf` databases.  #{subject.error? ? "Received the following error on access: `#{subject.error}`." : ''}"
        end
      end
    end
  end
end
