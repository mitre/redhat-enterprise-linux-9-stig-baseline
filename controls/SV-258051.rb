control 'SV-258051' do
  title 'All RHEL 9 local interactive users must have a home directory assigned in the /etc/passwd file.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', "Verify that interactive users on the system have a home directory assigned with the following command:
 
$ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd

smithk:x:1000:1000:smithk:/home/smithk:/bin/bash
scsaustin:x:1001:1001:scsaustin:/home/scsaustin:/bin/bash
djohnson:x:1002:1002:djohnson:/home/djohnson:/bin/bash

Inspect the output and verify that all interactive users (normally users with a user identifier (UID) greater that 1000) have a home directory defined.

If users home directory is not defined, this is a finding."
  desc 'fix', 'Create and assign home directories to all local interactive users on RHEL 9 that currently do not have a home directory assigned.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61792r926138_chk'
  tag severity: 'medium'
  tag gid: 'V-258051'
  tag rid: 'SV-258051r926140_rule'
  tag stig_id: 'RHEL-09-411060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61716r926139_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
