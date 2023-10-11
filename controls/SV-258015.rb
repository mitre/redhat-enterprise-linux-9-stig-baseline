control 'SV-258015' do
  title 'RHEL 9 must prevent a user from overriding the disabling of the graphical user interface automount function.'
  desc 'A nonprivileged account is any operating system account with authorizations of a nonprivileged user.

'
  desc 'check', %q(Verify RHEL 9 disables ability of the user to override the graphical user interface automount setting.

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user

system-db:local

Check that the automount setting is locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ grep 'automount-open' /etc/dconf/db/local.d/locks/* 

/org/gnome/desktop/media-handling/automount-open

If the command does not return at least the example result, this is a finding.)
  desc 'fix', 'Configure the GNOME desktop to not allow a user to change the setting that disables automated mounting of removable media.

Add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock" to prevent user modification:

/org/gnome/desktop/media-handling/automount-open

Then update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61756r926030_chk'
  tag severity: 'medium'
  tag gid: 'V-258015'
  tag rid: 'SV-258015r926032_rule'
  tag stig_id: 'RHEL-09-271025'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-61680r926031_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b', 'IA-3', 'IA-3']
end
