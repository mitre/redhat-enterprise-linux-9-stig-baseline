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
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61766r926060_chk'
  tag severity: 'medium'
  tag gid: 'V-258025'
  tag rid: 'SV-258025r926062_rule'
  tag stig_id: 'RHEL-09-271075'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-61690r926061_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
