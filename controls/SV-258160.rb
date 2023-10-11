control 'SV-258160' do
  title 'RHEL 9 audit system must take appropriate action when the audit files have reached maximum size.'
  desc 'It is critical that when the operating system is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.'
  desc 'check', 'Verify that RHEL 9 takes the appropriate action when the audit files have reached maximum size with the following command:

$ sudo grep max_log_file_action /etc/audit/auditd.conf

max_log_file_action = ROTATE

If the value of the "max_log_file_action" option is not "ROTATE", "SINGLE", or the line is commented out, ask the system administrator (SA)to indicate how the system takes appropriate action when an audit storage volume is full. If there is no evidence of appropriate action, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to rotate the audit log when it reaches maximum size.

Add or update the following line in "/etc/audit/auditd.conf" file:

max_log_file_action = ROTATE'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61901r926465_chk'
  tag severity: 'medium'
  tag gid: 'V-258160'
  tag rid: 'SV-258160r926467_rule'
  tag stig_id: 'RHEL-09-653055'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-61825r926466_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
