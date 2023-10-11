control 'SV-258139' do
  title 'RHEL 9 must be configured so that the file integrity tool verifies extended attributes.'
  desc 'RHEL 9 installation media ships with an optional file integrity tool called Advanced Intrusion Detection Environment (AIDE). AIDE is highly configurable at install time. This requirement assumes the "aide.conf" file is under the "/etc" directory.

Extended attributes in file systems are used to contain arbitrary data and file metadata with security implications.'
  desc 'check', 'Verify that AIDE is configured to verify extended attributes with the following command:

$ grep xattrs /etc/aide.conf 

All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux

If the "xattrs" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or extended attributes are not being checked by another file integrity tool, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to check file and directory extended attributes. 

If AIDE is installed, ensure the "xattrs" rule is present on all uncommented file and directory selection lists.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61880r926402_chk'
  tag severity: 'low'
  tag gid: 'V-258139'
  tag rid: 'SV-258139r926404_rule'
  tag stig_id: 'RHEL-09-651035'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61804r926403_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
