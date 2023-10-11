control 'SV-258164' do
  title 'RHEL 9 audit system must audit local events.'
  desc %q(Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

If option "local_events" isn't set to "yes" only events from network will be aggregated.

)
  desc 'check', %q(Verify that the RHEL 9 audit system is configured to audit local events with the following command:

$ sudo grep local_events /etc/audit/auditd.conf 

local_events = yes 

If "local_events" isn't set to "yes", if the command does not return a line, or the line is commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to generate audit records for local events by adding or updating the following line in "/etc/audit/auditd.conf":

local_events = yes 

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61905r926477_chk'
  tag severity: 'medium'
  tag gid: 'V-258164'
  tag rid: 'SV-258164r926479_rule'
  tag stig_id: 'RHEL-09-653075'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-61829r926478_fix'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-000366']
  tag nist: ['AU-12 a', 'CM-6 b']
end
