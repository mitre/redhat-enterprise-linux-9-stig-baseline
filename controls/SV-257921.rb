control 'SV-257921' do
  title 'RHEL 9 library files must be group-owned by root or a system account.'
  desc 'If RHEL 9 allowed any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 9 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify the system-wide shared library files are group-owned by "root" with the following command:

$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 ! -group root -exec ls -l {} \\;

If any system-wide shared library file is returned and is not group-owned by a required system account, this is a finding.'
  desc 'fix', 'Configure the system-wide shared library files (/lib, /lib64, /usr/lib and /usr/lib64) to be protected from unauthorized access.

Run the following command, replacing "[FILE]" with any library file not group-owned by "root".

$ sudo chgrp root [FILE]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61662r925748_chk'
  tag severity: 'medium'
  tag gid: 'V-257921'
  tag rid: 'SV-257921r925750_rule'
  tag stig_id: 'RHEL-09-232205'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-61586r925749_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
