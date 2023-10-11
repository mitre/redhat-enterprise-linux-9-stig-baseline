control 'SV-258229' do
  title 'RHEL 9 audit system must protect auditing rules from unauthorized change.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit RHEL 9 system activity.

In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back.  A system reboot would be noticeable, and a system administrator could then investigate the unauthorized changes.

'
  desc 'check', 'Verify the audit system prevents unauthorized changes with the following command:

$ sudo grep "^\\s*[^#]" /etc/audit/audit.rules | tail -1

-e 2

If the audit system is not set to be immutable by adding the "-e 2" option to the end of "/etc/audit/audit.rules", this is a finding.'
  desc 'fix', 'Configure the audit system to set the audit rules to be immutable by adding the following line to end of "/etc/audit/rules.d/audit.rules"

-e 2

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61970r926672_chk'
  tag severity: 'medium'
  tag gid: 'V-258229'
  tag rid: 'SV-258229r926674_rule'
  tag stig_id: 'RHEL-09-654275'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-61894r926673_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
