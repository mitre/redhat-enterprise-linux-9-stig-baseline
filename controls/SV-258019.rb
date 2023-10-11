control 'SV-258019' do
  title 'RHEL 9 must be able to initiate directly a session lock for all connection types using smart card when the smart card is removed.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 9 needs to provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.

'
  desc 'check', %q(Verify RHEL 9 enables a user's session lock until that user re-establishes access using established identification and authentication procedures with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ grep -R removal-action /etc/dconf/db/*

/etc/dconf/db/distro.d/20-authselect:removal-action='lock-screen'

If the "removal-action='lock-screen'" setting is missing or commented out from the dconf database files, this is a finding.)
  desc 'fix', %q(Configure RHEL 9 to enable a user's session lock until that user re-establishes access using established identification and authentication procedures.

Select or create an authselect profile and incorporate the "with-smartcard-lock-on-removal" feature with the following example:

$ sudo authselect select sssd with-smartcard with-smartcard-lock-on-removal

Alternatively, the dconf settings can be edited in the /etc/dconf/db/* location.

Add or update the [org/gnome/settings-daemon/peripherals/smartcard] section of the /etc/dconf/db/local.d/00-security-settings" database file and add or update the following lines:

[org/gnome/settings-daemon/peripherals/smartcard]
removal-action='lock-screen'

Then update the dconf system databases:

$ sudo dconf update)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61760r926042_chk'
  tag severity: 'medium'
  tag gid: 'V-258019'
  tag rid: 'SV-258019r926044_rule'
  tag stig_id: 'RHEL-09-271045'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-61684r926043_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a']
end
