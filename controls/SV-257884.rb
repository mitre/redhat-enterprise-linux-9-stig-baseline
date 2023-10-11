control 'SV-257884' do
  title 'RHEL 9 library files must have mode 755 or less permissive.'
  desc 'If RHEL 9 allowed any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 9 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify the system-wide shared library files contained in the following directories have mode "755" or less permissive with the following command:

$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec ls -l {} \\;

If any system-wide shared library file is found to be group-writable or world-writable, this is a finding.'
  desc 'fix', 'Configure the library files to be protected from unauthorized access. Run the following command, replacing "[FILE]" with any library file with a mode more permissive than 755.

$ sudo chmod 755 [FILE]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61625r925637_chk'
  tag severity: 'medium'
  tag gid: 'V-257884'
  tag rid: 'SV-257884r925639_rule'
  tag stig_id: 'RHEL-09-232020'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-61549r925638_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
