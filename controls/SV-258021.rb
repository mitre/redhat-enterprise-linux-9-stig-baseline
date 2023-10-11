control 'SV-258021' do
  title 'RHEL 9 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.

'
  desc 'check', %q(Verify RHEL 9 enables a user's session lock until that user re-establishes access using established identification and authentication procedures with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.desktop.screensaver lock-enabled

true

If the setting is "false", this is a finding.)
  desc 'fix', %q(Configure RHEL 9 to enable a user's session lock until that user re-establishes access using established identification and authentication procedures.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following example:

$ sudo vi /etc/dconf/db/local.d/00-screensaver

Edit the "[org/gnome/desktop/screensaver]" section of the database file and add or update the following lines:

# Set this to true to lock the screen when the screensaver activates
lock-enabled=true

Update the system databases:

$ sudo dconf update)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61762r926048_chk'
  tag severity: 'medium'
  tag gid: 'V-258021'
  tag rid: 'SV-258021r926050_rule'
  tag stig_id: 'RHEL-09-271055'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-61686r926049_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a']
end
