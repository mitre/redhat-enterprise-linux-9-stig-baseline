control 'SV-258172' do
  title 'RHEL 9 /etc/audit/auditd.conf file must have 0640 or less permissive to prevent unauthorized access.'
  desc "Without the capability to restrict the roles and individuals that can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify the mode of /etc/audit/auditd.conf with the command:

$ sudo stat -c "%a %n" /etc/audit/auditd.conf

640 /etc/audit/auditd.conf

If "/etc/audit/auditd.conf" does not have a mode of "0640", this is a finding.'
  desc 'fix', 'Set the mode of /etc/audit/auditd.conf file to 0640 with the command:

$ sudo chmod 0640 /etc/audit/auditd.conf'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61913r926501_chk'
  tag severity: 'medium'
  tag gid: 'V-258172'
  tag rid: 'SV-258172r926503_rule'
  tag stig_id: 'RHEL-09-653115'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-61837r926502_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
