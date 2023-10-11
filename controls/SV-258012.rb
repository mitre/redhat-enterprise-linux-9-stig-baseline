control 'SV-258012' do
  title 'RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

For U.S. Government systems, system use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.

'
  desc 'check', 'Verify RHEL 9 displays a banner before granting access to the operating system via a graphical user logon.

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable. 

Determine if the operating system displays a banner at the logon screen with the following command:

$ sudo grep banner-message-enable /etc/dconf/db/local.d/*

banner-message-enable=true

If "banner-message-enable" is set to "false", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via a graphical user logon.

Create a database to contain the system-wide graphical user logon settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/01-banner-message

Add the following lines to the [org/gnome/login-screen] section of the "/etc/dconf/db/local.d/01-banner-message":

[org/gnome/login-screen]

banner-message-enable=true

Run the following command to update the database:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61753r926021_chk'
  tag severity: 'medium'
  tag gid: 'V-258012'
  tag rid: 'SV-258012r926023_rule'
  tag stig_id: 'RHEL-09-271010'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-61677r926022_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
