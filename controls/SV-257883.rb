control 'SV-257883' do
  title 'RHEL 9 library directories must have mode 755 or less permissive.'
  desc 'If RHEL 9 allowed any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 9 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify the system-wide shared library directories have mode "755" or less permissive with the following command:

$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type d -exec ls -l {} \\;

If any system-wide shared library file is found to be group-writable or world-writable, this is a finding.'
  desc 'fix', 'Configure the system-wide shared library directories (/lib, /lib64, /usr/lib and /usr/lib64) to be protected from unauthorized access. 

Run the following command, replacing "[DIRECTORY]" with any library directory with a mode more permissive than 755.

$ sudo chmod 755 [DIRECTORY]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61624r925634_chk'
  tag severity: 'medium'
  tag gid: 'V-257883'
  tag rid: 'SV-257883r925636_rule'
  tag stig_id: 'RHEL-09-232015'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-61548r925635_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
