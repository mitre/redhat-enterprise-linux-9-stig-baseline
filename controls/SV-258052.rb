control 'SV-258052' do
  title 'All RHEL 9 local interactive user home directories defined in the /etc/passwd file must exist.'
  desc 'If a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon logon. This could create a denial of service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access.'
  desc 'check', "Verify the assigned home directories of all interactive users on the system exist with the following command:

$ sudo pwck -r 

user 'mailnull': directory 'var/spool/mqueue' does not exist

The output should not return any interactive users.

If users home directory does not exist, this is a finding."
  desc 'fix', 'Create home directories to all local interactive users that currently do not have a home directory assigned. Use the following commands to create the user home directory assigned in "/etc/ passwd":

Note: The example will be for the user wadea, who has a home directory of "/home/wadea", a user identifier (UID) of "wadea", and a Group Identifier (GID) of "users assigned" in "/etc/passwd".

$ sudo mkdir /home/wadea 
$ sudo chown wadea /home/wadea
$ sudo chgrp users /home/wadea
$ sudo chmod 0750 /home/wadea'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61793r926141_chk'
  tag severity: 'medium'
  tag gid: 'V-258052'
  tag rid: 'SV-258052r926143_rule'
  tag stig_id: 'RHEL-09-411065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61717r926142_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
