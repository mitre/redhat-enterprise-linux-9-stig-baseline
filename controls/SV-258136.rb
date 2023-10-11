control 'SV-258136' do
  title 'RHEL 9 must use a file integrity tool that is configured to use FIPS 140-3-approved cryptographic hashes for validating file contents and directories.'
  desc 'RHEL 9 installation media ships with an optional file integrity tool called Advanced Intrusion Detection Environment (AIDE). AIDE is highly configurable at install time. This requirement assumes the "aide.conf" file is under the "/etc" directory.

File integrity tools use cryptographic hashes for verifying file contents and directories have not been altered. These hashes must be FIPS 140-2/140-3-approved cryptographic hashes.'
  desc 'check', 'Verify that AIDE is configured to use FIPS 140-2/140-3 file hashing with the following command:

$ grep sha512 /etc/aide.conf 

All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux

If the "sha512" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or another file integrity tool is not using FIPS 140-2/140-3-approved cryptographic hashes for validating file contents and directories, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to use FIPS 140-2/140-3 cryptographic hashes for validating file and directory contents. 

If AIDE is installed, ensure the "sha512" rule is present on all uncommented file and directory selection lists. Exclude any log files, or files expected to change frequently, to reduce unnecessary notifications.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61877r926393_chk'
  tag severity: 'medium'
  tag gid: 'V-258136'
  tag rid: 'SV-258136r926395_rule'
  tag stig_id: 'RHEL-09-651020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61801r926394_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
