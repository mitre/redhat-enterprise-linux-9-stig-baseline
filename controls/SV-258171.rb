control 'SV-258171' do
  title 'RHEL 9 must allow only the information system security manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict the roles and individuals that can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify that the files in directory "/etc/audit/rules.d/" and "/etc/audit/auditd.conf" file have a mode of "0640" or less permissive with the following command:

$ sudo stat -c "%a %n"  /etc/audit/rules.d/*.rules

640 /etc/audit/rules.d/audit.rules 

If the files in the "/etc/audit/rules.d/" directory or the "/etc/audit/auditd.conf" file have a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Configure the files in directory "/etc/audit/rules.d/" and the "/etc/audit/auditd.conf" file to have a mode of "0640" with the following commands:

$ sudo chmod 0640 /etc/audit/rules.d/audit.rules
$ sudo chmod 0640 /etc/audit/rules.d/[customrulesfile].rules
$ sudo chmod 0640 /etc/audit/auditd.conf'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61912r926498_chk'
  tag severity: 'medium'
  tag gid: 'V-258171'
  tag rid: 'SV-258171r926500_rule'
  tag stig_id: 'RHEL-09-653110'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-61836r926499_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
