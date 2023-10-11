control 'SV-258030' do
  title 'RHEL 9 must prevent a user from overriding the disable-restart-buttons setting for the graphical user interface.'
  desc 'A user who is at the console can reboot the system at the login screen. If restart or shutdown buttons are pressed at the login screen, this can create the risk of short-term loss of availability of systems due to reboot.'
  desc 'check', 'Verify RHEL 9 prevents a user from overriding the disable-restart-buttons setting for graphical user interfaces. 

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user

system-db:local

Check that graphical settings are locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ grep disable-restart-buttons /etc/dconf/db/local.d/locks/* 

/org/gnome/login-screen/disable-restart-buttons

If the command does not return at least the example result, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent a user from overriding the disable-restart-buttons setting for graphical user interfaces. 

Create a database to contain the system-wide graphical user logon settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/locks/session

Add the following line to prevent nonprivileged users from modifying it:

/org/gnome/login-screen/disable-restart-buttons

Run the following command to update the database:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61771r926075_chk'
  tag severity: 'medium'
  tag gid: 'V-258030'
  tag rid: 'SV-258030r926077_rule'
  tag stig_id: 'RHEL-09-271100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61695r926076_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
