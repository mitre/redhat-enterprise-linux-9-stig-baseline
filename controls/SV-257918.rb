control 'SV-257918' do
  title 'RHEL 9 system commands must be owned by root.'
  desc 'If RHEL 9 allowed any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 9 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify the system commands contained in the following directories are owned by "root" with the following command:

$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin ! -user root -exec ls -l {} \\;

If any system commands are found to not be owned by root, this is a finding.'
  desc 'fix', 'Configure the system commands to be protected from unauthorized access.

Run the following command, replacing "[FILE]" with any system command file not owned by "root".

$ sudo chown root [FILE]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61659r925739_chk'
  tag severity: 'medium'
  tag gid: 'V-257918'
  tag rid: 'SV-257918r925741_rule'
  tag stig_id: 'RHEL-09-232190'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-61583r925740_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
