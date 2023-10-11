control 'SV-258053' do
  title "All RHEL 9 local interactive user home directories must be group-owned by the home directory owner's primary group."
  desc 'If the Group Identifier (GID) of a local interactive users home directory is not the same as the primary GID of the user, this would allow unauthorized access to the users files, and users that share the same group may not be able to access files that they legitimately should.'
  desc 'check', %q(Verify the assigned home directory of all local interactive users is group-owned by that user's primary GID with the following command:

Note: This may miss local interactive users that have been assigned a privileged user identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information. The returned directory "/home/wadea" is used as an example.

$ sudo ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)

drwxr-x--- 2 wadea admin 4096 Jun 5 12:41 wadea

Check the user's primary group with the following command:

$ sudo grep $(grep wadea /etc/passwd | awk -F: ‘{print $4}') /etc/group

admin:x:250:wadea,jonesj,jacksons

If the user home directory referenced in "/etc/passwd" is not group-owned by that user's primary GID, this is a finding.)
  desc 'fix', %q(Change the group owner of a local interactive user's home directory to the group found in "/etc/passwd". To change the group owner of a local interactive user's home directory, use the following command:

Note: The example will be for the user "wadea", who has a home directory of "/home/wadea", and has a primary group of users.

$ sudo chgrp users /home/wadea)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61794r926144_chk'
  tag severity: 'medium'
  tag gid: 'V-258053'
  tag rid: 'SV-258053r926146_rule'
  tag stig_id: 'RHEL-09-411070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61718r926145_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
