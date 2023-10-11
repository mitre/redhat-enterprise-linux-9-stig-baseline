control 'SV-257919' do
  title 'RHEL 9 system commands must be group-owned by root or a system account.'
  desc 'If RHEL 9 allowed any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 9 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify the system commands contained in the following directories are group-owned by "root", or a required system account, with the following command:

$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -exec ls -l {} \\;

If any system commands are returned and is not group-owned by a required system account, this is a finding.'
  desc 'fix', 'Configure the system commands to be protected from unauthorized access.

Run the following command, replacing "[FILE]" with any system command file not group-owned by "root" or a required system account.

$ sudo chgrp root [FILE]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61660r925742_chk'
  tag severity: 'medium'
  tag gid: 'V-257919'
  tag rid: 'SV-257919r925744_rule'
  tag stig_id: 'RHEL-09-232195'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-61584r925743_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
