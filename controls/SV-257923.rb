control 'SV-257923' do
  title 'RHEL 9 library directories must be group-owned by root or a system account.'
  desc 'If RHEL 9 allowed any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 9 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', %q(Verify the system-wide shared library directories are group-owned by "root" with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 ! -group root -type d -exec stat -c "%n %G" '{}' \;

If any system-wide shared library directory is returned and is not group-owned by a required system account, this is a finding.)
  desc 'fix', 'Configure the system-wide shared library directories (/lib, /lib64, /usr/lib and /usr/lib64) to be protected from unauthorized access.

Run the following command, replacing "[DIRECTORY]" with any library directory not group-owned by "root".

$ sudo chgrp root [DIRECTORY]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61664r925754_chk'
  tag severity: 'medium'
  tag gid: 'V-257923'
  tag rid: 'SV-257923r925756_rule'
  tag stig_id: 'RHEL-09-232215'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-61588r925755_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
