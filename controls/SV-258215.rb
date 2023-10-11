control 'SV-258215' do
  title 'Successful/unsuccessful uses of the umount system call in RHEL 9 must generate an audit record.'
  desc 'The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.

'
  desc 'check', 'Verify that RHEL 9 generates an audit record for all uses of the "umount" and system call with the following command:

$ sudo grep "umount" /etc/audit/audit.* 

If the system is configured to audit this activity, it will return a line like the following:

-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=unset -k privileged-umount

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "umount" system call by adding or updating the following rules in "/etc/audit/audit.rules" and adding the following rules to "/etc/audit/rules.d/perm_mod.rules" or updating the existing rules in files in the "/etc/audit/rules.d/" directory:

-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=unset -k perm_mod -a always,exit -F arch=b64 -S umount -F auid>=1000 -F auid!=unset -k perm_mod

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61956r926630_chk'
  tag severity: 'medium'
  tag gid: 'V-258215'
  tag rid: 'SV-258215r926632_rule'
  tag stig_id: 'RHEL-09-654205'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-61880r926631_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
