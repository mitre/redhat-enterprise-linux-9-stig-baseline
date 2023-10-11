control 'SV-258029' do
  title 'RHEL 9 must disable the ability of a user to restart the system from the login screen.'
  desc 'A user who is at the console can reboot the system at the login screen. If restart or shutdown buttons are pressed at the login screen, this can create the risk of short-term loss of availability of systems due to reboot.'
  desc 'check', %q(Verify RHEL 9 disables a user's ability to restart the system with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ grep -R disable-restart-buttons /etc/dconf/db/*

/etc/dconf/db/distro.d/20-authselect:disable-restart-buttons='true'

If the "disable-restart-button" setting is not set to "true", is missing or commented out from the dconf database files, this is a finding.)
  desc 'fix', %q(Configure RHEL 9 to disable a user's ability to restart the system.

Add or update the [org/gnome/settings-daemon/] section of the /etc/dconf/db/local.d/00-security-settings" database file and add or update the following lines:

[org/gnome/settings-daemon/peripherals/smartcard]
disable-restart-buttons='true'

Then update the dconf system databases:

$ sudo dconf update)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61770r926072_chk'
  tag severity: 'medium'
  tag gid: 'V-258029'
  tag rid: 'SV-258029r926074_rule'
  tag stig_id: 'RHEL-09-271095'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61694r926073_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
