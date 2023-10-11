control 'SV-257815' do
  title 'RHEL 9 must disable acquiring, saving, and processing core dumps.'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.'
  desc 'check', 'Verify RHEL 9 is not configured to acquire, save, or process core dumps with the following command:

$ sudo systemctl status systemd-coredump.socket

systemd-coredump.socket
Loaded: masked (Reason: Unit systemd-coredump.socket is masked.)
Active: inactive (dead)

If the "systemd-coredump.socket" is loaded and not masked and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the system to disable the systemd-coredump.socket with the following command:

$ sudo systemctl mask --now systemd-coredump.socket

Created symlink /etc/systemd/system/systemd-coredump.socket -> /dev/null

Reload the daemon for this change to take effect.

$ sudo systemctl daemon-reload'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61556r925430_chk'
  tag severity: 'medium'
  tag gid: 'V-257815'
  tag rid: 'SV-257815r925432_rule'
  tag stig_id: 'RHEL-09-213100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61480r925431_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
