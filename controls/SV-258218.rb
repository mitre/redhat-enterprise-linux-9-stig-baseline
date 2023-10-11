control 'SV-258218' do
  title 'RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.d/ directory.'
  desc 'The actions taken by system administrators must be audited to keep a record of what was executed on the system, as well as for accountability purposes. Editing the sudoers file may be sign of an attacker trying to establish persistent methods to a system, auditing the editing of the sudoers files mitigates this risk.

'
  desc 'check', 'Verify RHEL 9 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/sudoers.d/" with the following command:

$ sudo auditctl -l | grep /etc/sudoers.d

-w /etc/sudoers.d/ -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/sudoers.d/".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /etc/sudoers.d/ -p wa -k identity

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61959r926639_chk'
  tag severity: 'medium'
  tag gid: 'V-258218'
  tag rid: 'SV-258218r926641_rule'
  tag stig_id: 'RHEL-09-654220'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-61883r926640_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000304-GPOS-00121', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000476-GPOS-00221']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130', 'CCI-002132', 'CCI-002884']
  tag nist: ['AC-2 (4)', 'AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'MA-4 (1) (a)']
end
