control 'SV-257922' do
  title 'RHEL 9 library directories must be owned by root.'
  desc 'If RHEL 9 allowed any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 9 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', %q(Verify the system-wide shared library directories are owned by "root" with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \;

If any system-wide shared library directory is not owned by root, this is a finding.)
  desc 'fix', 'Configure the system-wide shared library directories within (/lib, /lib64, /usr/lib and /usr/lib64) to be protected from unauthorized access.

Run the following command, replacing "[DIRECTORY]" with any library directory not owned by "root".

$ sudo chown root [DIRECTORY]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61663r925751_chk'
  tag severity: 'medium'
  tag gid: 'V-257922'
  tag rid: 'SV-257922r925753_rule'
  tag stig_id: 'RHEL-09-232210'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-61587r925752_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
