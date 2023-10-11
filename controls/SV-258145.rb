control 'SV-258145' do
  title 'RHEL 9 must be configured to offload audit records onto a different system from the system being audited via syslog.'
  desc 'The auditd service does not include the ability to send audit records to a centralized server for management directly. However, it can use a plug-in for audit event multiplexor (audispd) to pass audit records to the local syslog server.

'
  desc 'check', 'Verify RHEL 9 is configured use the audisp-remote syslog service with the following command:

$ sudo grep active /etc/audit/plugins.d/syslog.conf 

active = yes

If the "active" keyword does not have a value of "yes", the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Edit the /etc/audit/plugins.d/syslog.conf file and add or update the "active" option:

active = yes

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61886r926420_chk'
  tag severity: 'medium'
  tag gid: 'V-258145'
  tag rid: 'SV-258145r926422_rule'
  tag stig_id: 'RHEL-09-652035'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-61810r926421_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
