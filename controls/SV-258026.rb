control 'SV-258026' do
  title 'RHEL 9 must prevent a user from overriding the session lock-delay setting for the graphical user interface.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not logout because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, the GNOME desktop can be configured to identify when a user's session has idled and take action to initiate the session lock. As such, users should not be allowed to change session settings."
  desc 'check', 'Verify RHEL 9 prevents a user from overriding settings for graphical user interfaces. 

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user

system-db:local

Check that graphical settings are locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ sudo grep -i lock-delay /etc/dconf/db/local.d/locks/*

/org/gnome/desktop/screensaver/lock-delay

If the command does not return at least the example result, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent a user from overriding settings for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command: 

Note: The example below is using the database "local" for the system, so if the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

$ sudo touch /etc/dconf/db/local.d/locks/session

Add the following setting to prevent nonprivileged users from modifying it:

/org/gnome/desktop/screensaver/lock-delay'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61767r926063_chk'
  tag severity: 'medium'
  tag gid: 'V-258026'
  tag rid: 'SV-258026r926065_rule'
  tag stig_id: 'RHEL-09-271080'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-61691r926064_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
