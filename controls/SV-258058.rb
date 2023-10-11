control 'SV-258058' do
  title 'RHEL 9 must not have unauthorized accounts.'
  desc 'Accounts providing no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Verify that there are no unauthorized interactive user accounts with the following command:

$ less /etc/passwd  

root:x:0:0:root:/root:/bin/bash
...
games:x:12:100:games:/usr/games:/sbin/nologin
scsaustin:x:1001:1001:scsaustin:/home/scsaustin:/bin/bash
djohnson:x:1002:1002:djohnson:/home/djohnson:/bin/bash

Interactive user account, generally will have a user identifier (UID) of 1000 or greater, a home directory in a specific partition, and an interactive shell.

Obtain the list of interactive user accounts authorized to be on the system from the system administrator or information system security officer (ISSO) and compare it to the list of local interactive user accounts on the system.

If there are unauthorized local user accounts on the system, this is a finding.'
  desc 'fix', 'Remove unauthorized local interactive user accounts with the following command where <unauthorized_user> is the unauthorized account:

$ sudo userdel  <unauthorized_user>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61799r926159_chk'
  tag severity: 'medium'
  tag gid: 'V-258058'
  tag rid: 'SV-258058r926161_rule'
  tag stig_id: 'RHEL-09-411095'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61723r926160_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
