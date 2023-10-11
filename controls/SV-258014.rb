control 'SV-258014' do
  title 'RHEL 9 must disable the graphical user interface automount function unless required.'
  desc 'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.

'
  desc 'check', 'Verify RHEL 9 disables the graphical user interface automount function with the following command:

Note: This requirement assumes the use of the RHEL 9 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ gsettings get org.gnome.desktop.media-handling automount-open 

false

If "automount-open" is set to "true", and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the GNOME desktop to disable automated mounting of removable media.

The dconf settings can be edited in the /etc/dconf/db/* location.

Update the [org/gnome/desktop/media-handling] section of the "/etc/dconf/db/local.d/00-security-settings" database file and add or update the following lines:

[org/gnome/desktop/media-handling]
automount-open=false

Then update the dconf system databases:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61755r926027_chk'
  tag severity: 'medium'
  tag gid: 'V-258014'
  tag rid: 'SV-258014r926029_rule'
  tag stig_id: 'RHEL-09-271020'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-61679r926028_fix'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000778', 'CCI-001958']
  tag nist: ['CM-6 b', 'IA-3', 'IA-3']
end
