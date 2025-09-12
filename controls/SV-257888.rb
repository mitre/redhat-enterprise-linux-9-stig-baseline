control 'SV-257888' do
  title 'RHEL 9 permissions of cron configuration files and directories must not be modified from the operating system defaults.'
  desc 'If the permissions of cron configuration files or directories are modified from the operating system defaults, it may be possible for individuals to insert unauthorized cron jobs that perform unauthorized actions, including potentially escalating privileges.'
  desc 'check', %q(Run the following command to verify that the owner, group, and mode of cron configuration files and directories match the operating system defaults:

$ rpm --verify cronie crontabs | awk '! ($2 == "c" && $1 ~ /^.\..\.\.\.\..\./) {print $0}'

If the command returns any output, this is a finding.)
  desc 'fix', 'Run the following commands to restore the permissions of cron configuration files and directories to the operating system defaults:

$ sudo dnf reinstall cronie crontabs
$ rpm --setugids cronie crontabs
$ rpm --setperms cronie crontabs'
  impact 0.5
  tag check_id: 'C-61629r1069376_chk'
  tag severity: 'medium'
  tag gid: 'V-257888'
  tag rid: 'SV-257888r1069378_rule'
  tag stig_id: 'RHEL-09-232040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61553r1069377_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  output = command(%q(rpm --verify cronie crontabs | awk '! ($2 == "c" && $1 ~ /^.\..\.\.\.\..\./) {print $0}')).stdout.strip

  describe 'Cron configuration files and directories' do
    it 'match the OS default owner, group, and mode' do
      expect(output).to be_empty, "Failing configuration files and directories:\n#{output}"
    end
  end
end
