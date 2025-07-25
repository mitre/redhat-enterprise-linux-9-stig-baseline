control 'SV-257919' do
  title 'RHEL 9 system commands must be group-owned by root or a system account.'
  desc 'If RHEL 9 allowed any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 9 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify the system commands contained in the following directories are group-owned by "root", or a required system account, with the following command:

$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin ! -group root -exec stat -L -c "%G %n" {} \\;

If any system commands are returned and are not group-owned by a required system account, this is a finding.'
  desc 'fix', 'Configure the system commands to be protected from unauthorized access.

    Run the following command, replacing "[FILE]" with any system command
file not group-owned by "root" or a required system account.

    $ sudo chgrp root [FILE]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-257919'
  tag rid: 'SV-257919r1044979_rule'
  tag stig_id: 'RHEL-09-232195'
  tag fix_id: 'F-61584r925743_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  failing_files = command("find -L #{input('system_command_dirs').join(' ')} ! -group root -exec ls -d {} \\;").stdout.split("\n")

  describe 'System commands' do
    it 'should be group-owned by root' do
      expect(failing_files).to be_empty, "Files not group-owned by root:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
