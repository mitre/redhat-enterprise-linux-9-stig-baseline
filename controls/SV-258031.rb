control 'SV-258031' do
  title 'RHEL 9 must disable the ability of a user to accidentally press Ctrl-Alt-Del and cause a system to shut down or reboot.'
  desc 'A locally logged-in user who presses Ctrl-Alt-Del, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot.'
  desc 'check', %q(Verify RHEL 9 is configured to ignore the Ctrl-Alt-Del sequence in the GNOME desktop with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.settings-daemon.plugins.media-keys logout 

"['']"

If the GNOME desktop is configured to shut down when Ctrl-Alt-Del is pressed, this is a finding.)
  desc 'fix', "Configure RHEL 9 to ignore the Ctrl-Alt-Del sequence in the GNOME desktop.

Add or update the [org/gnome/settings-daemon/plugins/media-keys] section of the /etc/dconf/db/local.d/00-security-settings database file and add or update the following lines:

[org/gnome/settings-daemon/plugins/media-keys]
logout=['']

Run the following command to update the database:

$ sudo dconf update"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61772r926078_chk'
  tag severity: 'medium'
  tag gid: 'V-258031'
  tag rid: 'SV-258031r926080_rule'
  tag stig_id: 'RHEL-09-271105'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61696r926079_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
