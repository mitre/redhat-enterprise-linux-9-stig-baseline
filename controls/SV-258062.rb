control 'SV-258062' do
  title 'Local RHEL 9 initialization files must not execute world-writable programs.'
  desc 'If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.'
  desc 'check', 'Verify that local initialization files do not execute world-writable programs with the following command:

Note: The example will be for a system that is configured to create user home directories in the "/home" directory.

$ sudo find /home -perm -002 -type f -name ".[^.]*" -exec ls -ld {} \\; 

If any local initialization files are found to reference world-writable files, this is a finding.'
  desc 'fix', 'Set the mode on files being executed by the local initialization files with the following command:

$ sudo chmod 0755 <file>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61803r926171_chk'
  tag severity: 'medium'
  tag gid: 'V-258062'
  tag rid: 'SV-258062r926173_rule'
  tag stig_id: 'RHEL-09-411115'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61727r926172_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
