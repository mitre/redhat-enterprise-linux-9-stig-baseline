control 'SV-257928' do
  title 'All RHEL 9 world-writable directories must be owned by root, sys, bin, or an application user.'
  desc 'If a world-writable directory is not owned by root, sys, bin, or an application user identifier (UID), unauthorized users may be able to modify files created by others.

The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.

'
  desc 'check', 'Verify that world writable directories are owned by root, a system account, or an application account with the following command. It will discover and print world-writable directories that are not owned by root.  Run it once for each local partition [PART]:

$ sudo find  PART  -xdev -type d -perm -0002 -uid +0 -print 

If there is output, this is a finding.'
  desc 'fix', 'Configure all public directories to be owned by root or a system account to prevent unauthorized and unintended information transferred via shared system resources.

Set the owner of all public directories as root or a system account using the command, replace "[Public Directory]" with any directory path not owned by root or a system account:

$ sudo chown root [Public Directory]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61669r925769_chk'
  tag severity: 'medium'
  tag gid: 'V-257928'
  tag rid: 'SV-257928r925771_rule'
  tag stig_id: 'RHEL-09-232240'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61593r925770_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000138-GPOS-00069']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001090']
  tag nist: ['CM-6 b', 'SC-4']
end
