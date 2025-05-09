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
  ref 'DPMS Target Red Hat Enterprise Linux 9'
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

  cron_dirs = command('find /etc/cron* -type d').stdout.split("\n")
  mode = input('expected_modes')['cron_dirs']

  non_compliant_cron_dirs = cron_dirs.select { |dir| file(dir).more_permissive_than?(mode) }

  describe 'All cron directories' do
    it "have a mode of '#{mode}' or less permissive" do
      expect(non_compliant_cron_dirs).to be_empty, "Failing directories:\n\t- #{non_compliant_cron_dirs.join("\n\t- ")}"
    end
  end
end
