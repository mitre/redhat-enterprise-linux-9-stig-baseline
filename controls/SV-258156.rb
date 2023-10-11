control 'SV-258156' do
  title 'RHEL 9 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.'
  desc 'check', 'Verify RHEL 9 takes action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity with the following command:

$ sudo grep -w space_left /etc/audit/auditd.conf

space_left = 25%

If the value of the "space_left" keyword is not set to 25 percent of the storage volume allocated to audit logs, or if the line is commented out, ask the system administrator (SA) to indicate how the system is providing real-time alerts to the SA and information system security officer (ISSO). If the "space_left" value is not configured to the correct value, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to initiate an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity by adding/modifying the following line in the /etc/audit/auditd.conf file.

space_left  = 25%'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61897r926453_chk'
  tag severity: 'medium'
  tag gid: 'V-258156'
  tag rid: 'SV-258156r926455_rule'
  tag stig_id: 'RHEL-09-653035'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-61821r926454_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
