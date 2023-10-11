control 'SV-258017' do
  title 'RHEL 9 must prevent a user from overriding the disabling of the graphical user interface autorun function.'
  desc 'Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.

'
  desc 'check', %q(Verify RHEL 9 disables ability of the user to override the graphical user interface autorun setting.

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user

system-db:local

Check that the automount setting is locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ grep 'autorun-never' /etc/dconf/db/local.d/locks/* 

/org/gnome/desktop/media-handling/autorun-never

If the command does not return at least the example result, this is a finding.)
  desc 'fix', 'Configure the GNOME desktop to not allow a user to change the setting that disables autorun on removable media.

Add the following line to "/etc/dconf/db/local.d/locks/00-security-settings-lock" to prevent user modification:

/org/gnome/desktop/media-handling/autorun-never

Then update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61758r926036_chk'
  tag severity: 'medium'
  tag gid: 'V-258017'
  tag rid: 'SV-258017r926038_rule'
  tag stig_id: 'RHEL-09-271035'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-61682r926037_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b', 'IA-3', 'IA-3']
end
