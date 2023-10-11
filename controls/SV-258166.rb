control 'SV-258166' do
  title 'RHEL 9 audit log directory must be owned by root to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

'
  desc 'check', 'Verify the audit logs directory is owned by "root". 

First determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Then using the location of the audit log file, determine if the audit log directory is owned by "root" using the following command:

$ sudo ls -ld /var/log/audit

drwx------ 2 root root 23 Jun 11 11:56 /var/log/audit

If the audit log directory is not owned by "root", this is a finding.'
  desc 'fix', 'Configure the audit log to be protected from unauthorized read access by setting the correct owner as "root" with the following command:

$ sudo chown root /var/log/audit'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61907r926483_chk'
  tag severity: 'medium'
  tag gid: 'V-258166'
  tag rid: 'SV-258166r926485_rule'
  tag stig_id: 'RHEL-09-653085'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-61831r926484_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'SI-11 b']
end
