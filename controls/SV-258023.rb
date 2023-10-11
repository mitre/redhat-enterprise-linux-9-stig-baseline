control 'SV-258023' do
  title 'RHEL 9 must automatically lock graphical user sessions after 15 minutes of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not logout because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, the GNOME desktop can be configured to identify when a user's session has idled and take action to initiate a session lock.

"
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
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61764r926054_chk'
  tag severity: 'medium'
  tag gid: 'V-258023'
  tag rid: 'SV-258023r926056_rule'
  tag stig_id: 'RHEL-09-271065'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-61688r926055_fix'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012']
  tag 'documentable'
  tag cci: ['CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 a', 'AC-11 (1)']
end
