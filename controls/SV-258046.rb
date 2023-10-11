control 'SV-258046' do
  title 'RHEL 9 system accounts must not have an interactive login shell.'
  desc 'Ensuring shells are not given to system accounts upon login makes it more difficult for attackers to make use of system accounts.'
  desc 'check', %q(Verify that system accounts must not have an interactive login shell with the following command:

$ awk -F: '($3<1000){print $1 ":" $3 ":" $7}' /etc/passwd

root:0:/bin/bash
bin:1:/sbin/nologin
daemon:2:/sbin/nologin
adm:3:/sbin/nologin
lp:4:/sbin/nologin

Identify the system accounts from this listing that do not have a nologin shell.

If any system account (other than the root account) has a login shell and it is not documented with the information system security officer (ISSO), this is a finding.)
  desc 'fix', 'Configure RHEL 9 so that all noninteractive accounts on the system do not have an interactive shell assigned to them.

If the system account needs a shell assigned for mission operations, document the need with the information system security officer (ISSO).

Run the following command to disable the interactive shell for a specific noninteractive user account:

Replace <user> with the user that has a login shell.

$ sudo usermod --shell /sbin/nologin <user>

Do not perform the steps in this section on the root account. Doing so will cause the system to become inaccessible.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61787r926123_chk'
  tag severity: 'medium'
  tag gid: 'V-258046'
  tag rid: 'SV-258046r926125_rule'
  tag stig_id: 'RHEL-09-411035'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61711r926124_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
