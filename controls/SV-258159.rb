control 'SV-258159' do
  title 'RHEL 9 must take action when allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity.'
  desc 'If action is not taken when storage volume reaches 95 percent utilization, the auditing system may fail when the storage volume reaches capacity.'
  desc 'check', 'Verify that RHEL 9 is configured to take action in the event of allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity with the following command:

$ sudo grep admin_space_left_action /etc/audit/auditd.conf

admin_space_left_action = single

If the value of the "admin_space_left_action" is not set to "single", or if the line is commented out, ask the system administrator (SA) to indicate how the system is providing real-time alerts to the SA and information system security officer (ISSO).

If there is no evidence that real-time alerts are configured on the system, this is a finding.'
  desc 'fix', 'Configure "auditd" service  to take action in the event of allocated audit record storage volume reaches 95 percent of the repository maximum audit record storage capacity.

Edit the following line in "/etc/audit/auditd.conf" to ensure that the system is forced into single user mode in the event the audit record storage volume is about to reach maximum capacity:

admin_space_left_action = single 

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61900r926462_chk'
  tag severity: 'medium'
  tag gid: 'V-258159'
  tag rid: 'SV-258159r926464_rule'
  tag stig_id: 'RHEL-09-653050'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-61824r926463_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
