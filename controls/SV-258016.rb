control 'SV-258016' do
  title 'RHEL 9 must disable the graphical user interface autorun function unless required.'
  desc 'Allowing autorun commands to execute may introduce malicious code to a system. Configuring this setting prevents autorun commands from executing.'
  desc 'check', 'Verify RHEL 9 disables the graphical user interface autorun function with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.desktop.media-handling autorun-never 

true

If "autorun-never" is set to "false", and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the GNOME desktop to disable the autorun function on removable media.

The dconf settings can be edited in the /etc/dconf/db/* location.

Update the [org/gnome/desktop/media-handling] section of the "/etc/dconf/db/local.d/00-security-settings" database file and add or update the following lines:

[org/gnome/desktop/media-handling]
autorun-never=true

Then update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61757r926033_chk'
  tag severity: 'medium'
  tag gid: 'V-258016'
  tag rid: 'SV-258016r926035_rule'
  tag stig_id: 'RHEL-09-271030'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61681r926034_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
