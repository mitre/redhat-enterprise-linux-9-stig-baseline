control 'SV-258165' do
  title 'RHEL 9 audit logs must be group-owned by root or by a restricted logging group to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

'
  desc 'check', 'Verify the audit logs are group-owned by "root" or a restricted logging group. 

First determine if a group other than "root" has been assigned to the audit logs with the following command:

$ sudo grep log_group /etc/audit/auditd.conf

Then determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Then using the location of the audit log file, determine if the audit log is group-owned by "root" using the following command:

$ sudo stat -c "%G %n" /var/log/audit/audit.log

root /var/log/audit/audit.log

If the audit log is not group-owned by "root" or the configured alternative logging group, this is a finding.'
  desc 'fix', %q(Change the group of the directory of "/var/log/audit" to be owned by a correct group.

Identify the group that is configured to own audit log:

$ sudo grep -P '^[ ]*log_group[ ]+=.*$' /etc/audit/auditd.conf

Change the ownership to that group:

$ sudo chgrp ${GROUP} /var/log/audit)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61906r926480_chk'
  tag severity: 'medium'
  tag gid: 'V-258165'
  tag rid: 'SV-258165r926482_rule'
  tag stig_id: 'RHEL-09-653080'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-61830r926481_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'SI-11 b']
end
