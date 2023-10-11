control 'SV-258162' do
  title 'RHEL 9 must take appropriate action when the internal event queue is full.'
  desc 'The audit system should have an action setup in the event the internal event queue becomes full so that no data is lost.  Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

'
  desc 'check', 'Verify that RHEL 9 audit system is configured to take an appropriate action when the internal event queue is full:

$ sudo grep -i overflow_action /etc/audit/auditd.conf 

overflow_action = syslog

If the value of the "overflow_action" option is not set to "syslog", "single", "halt" or the line is commented out, ask the system administrator (SA) to indicate how the audit logs are offloaded to a different system or media.

If there is no evidence that the transfer of the audit logs being offloaded to another system or media takes appropriate action if the internal event queue becomes full, this is a finding.'
  desc 'fix', 'Edit the /etc/audit/auditd.conf file and add or update the "overflow_action" option:

overflow_action = syslog

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61903r926471_chk'
  tag severity: 'medium'
  tag gid: 'V-258162'
  tag rid: 'SV-258162r926473_rule'
  tag stig_id: 'RHEL-09-653065'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-61827r926472_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
