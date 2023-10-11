control 'SV-258013' do
  title 'RHEL 9 must prevent a user from overriding the banner-message-enable setting for the graphical user interface.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

For U.S. Government systems, system use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.

'
  desc 'check', 'Verify RHEL 9 prevents a user from overriding settings for graphical user interfaces. 

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user

system-db:local

Check that graphical settings are locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ sudo grep banner-message-enable /etc/dconf/db/local.d/* 

/org/gnome/login-screen/banner-message-enable

If the output is not "/org/gnome/login-screen/banner-message-enable", the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent a user from overriding the banner setting for graphical user interfaces. 

Create a database to contain the system-wide graphical user logon settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/locks/session

Add the following setting to prevent nonprivileged users from modifying it:

banner-message-enable

Run the following command to update the database:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61754r926024_chk'
  tag severity: 'medium'
  tag gid: 'V-258013'
  tag rid: 'SV-258013r926026_rule'
  tag stig_id: 'RHEL-09-271015'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-61678r926025_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
