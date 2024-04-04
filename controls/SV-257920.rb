control 'SV-257920' do
  title 'RHEL 8 library files must be owned by root.'
  desc 'If RHEL 8 were to allow any user to make changes to software
libraries, then those changes might be implemented without undergoing the
appropriate testing and approvals that are part of a robust change management
process.

    This requirement applies to RHEL 8 with software libraries that are
accessible and configurable, as in the case of interpreted languages. Software
libraries also include privileged programs that execute with escalated
privileges. Only qualified and authorized individuals will be allowed to obtain
access to information system components for purposes of initiating changes,
including upgrades and modifications.'
  desc 'check', 'Verify the system-wide shared library files are owned by "root" with the
following command:

    $ sudo find -L /lib /lib64 /usr/lib /usr/lib64 ! -user root -exec ls -l {}
\\;

    If any system wide shared library file is returned, this is a finding.'
  desc 'fix', 'Configure the system-wide shared library files (/lib, /lib64, /usr/lib and
/usr/lib64) to be protected from unauthorized access.

    Run the following command, replacing "[FILE]" with any library file not
owned by "root".

    $ sudo chown root [FILE]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-230261'
  tag rid: 'SV-257920r627750_rule'
  tag stig_id: 'RHEL-08-010340'
  tag fix_id: 'F-32905r567530_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  failing_files = command("find -L #{input('system_libraries').join(' ')} ! -user root -exec ls -d {} \\;").stdout.split("\n")

  describe 'System libraries' do
    it 'should be owned by root' do
      expect(failing_files).to be_empty, "Files not owned by root:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
