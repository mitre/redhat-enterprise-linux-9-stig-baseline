control 'SV-258022' do
  title 'RHEL 9 must prevent a user from overriding the screensaver lock-enabled setting for the graphical user interface.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled.

Implementing session settings will have little value if a user is able to manipulate these settings from the defaults prescribed in the other requirements of this implementation guide.

"
  desc 'check', 'Verify RHEL 9 prevents a user from overriding settings for graphical user interfaces. 

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user

system-db:local

Check that graphical settings are locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ sudo grep -i lock-enabled /etc/dconf/db/local.d/locks/*

/org/gnome/desktop/screensaver/lock-enabled

If the command does not return at least the example result, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent a user from overriding settings for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command: 

Note: The example below is using the database "local" for the system, so if the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

$ sudo touch /etc/dconf/db/local.d/locks/session

Add the following setting to prevent nonprivileged users from modifying it:

/org/gnome/desktop/screensaver/lock-enabled'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61763r926051_chk'
  tag severity: 'medium'
  tag gid: 'V-258022'
  tag rid: 'SV-258022r926053_rule'
  tag stig_id: 'RHEL-09-271060'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-61687r926052_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a']
end
