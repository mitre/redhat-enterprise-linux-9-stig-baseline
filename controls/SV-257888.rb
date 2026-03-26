control 'SV-257888' do
  title 'RHEL 9 permissions of cron configuration files and directories must not be modified from the operating system defaults.'
  desc 'If the permissions of cron configuration files or directories are modified from the operating system defaults, it may be possible for individuals to insert unauthorized cron jobs that perform unauthorized actions, including potentially escalating privileges.'
  desc 'check', %q(Run the following command to verify that the owner, group, and mode of cron configuration files and directories match the operating system defaults:

$ rpm --verify cronie crontabs | awk '! ($2 == "c" && $1 ~ /^.\..\.\.\.\..\./) {print $0}'

If the command returns any output, this is a finding.

If there are findings, run the following command to determine what the permissions are:

$ ls -ld /etc/cron*
drwxr-xr-x. 2 root root  21 Oct  3  2024 /etc/cron.d
drwxr-xr-x. 2 root root   6 May  1 09:03 /etc/cron.daily
-rw-r--r--. 1 root root   0 Oct  3  2024 /etc/cron.deny
drwxr-xr-x. 2 root root  22 Mar  5 12:49 /etc/cron.hourly
drwxr-xr-x. 2 root root   6 Mar 23  2022 /etc/cron.monthly
-rw-r--r--. 1 root root 451 Mar 23  2022 /etc/crontab
drwxr-xr-x. 2 root root   6 Mar 23  2022 /etc/cron.weekly)
  desc 'fix', 'Run the following commands to restore the permissions of cron configuration files and directories to the operating system defaults:

$ sudo dnf reinstall cronie crontabs
$ rpm --setugids cronie crontabs
$ rpm --setperms cronie crontabs'
  impact 0.5
  tag check_id: 'C-61629r1134909_chk'
  tag severity: 'medium'
  tag gid: 'V-257888'
  tag rid: 'SV-257888r1134910_rule'
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
