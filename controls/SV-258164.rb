control 'SV-258164' do
  title 'RHEL 9 audit system must audit local events.'
  desc %q(Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

If option "local_events" isn't set to "yes" only events from network will be aggregated.)
  desc 'check', %q(Verify that the RHEL 9 audit system is configured to audit local events with the following command:

$ sudo grep local_events /etc/audit/auditd.conf

local_events = yes

If "local_events" isn't set to "yes", if the command does not return a line, or the line is commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to generate audit records for local events by adding or updating the following line in "/etc/audit/auditd.conf":

local_events = yes

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag gid: 'V-258164'
  tag rid: 'SV-258164r926479_rule'
  tag stig_id: 'RHEL-09-653075'
  tag fix_id: 'F-61829r926478_fix'
  tag cci: ['CCI-000366', 'CCI-000169']
  tag nist: ['CM-6 b', 'AU-12 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe parse_config_file('/etc/audit/auditd.conf') do
    its('local_events') { should eq 'yes' }
  end
end
