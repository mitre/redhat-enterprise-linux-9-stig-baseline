control 'SV-258154' do
  title 'RHEL 9 audit system must take appropriate action when the audit storage volume is full.'
  desc 'It is critical that when the operating system is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.'
  desc 'check', 'Verify RHEL 9 takes the appropriate action when the audit storage volume is full. 

Check that RHEL 9 takes the appropriate action when the audit storage volume is full with the following command:

$ sudo grep disk_full_action /etc/audit/auditd.conf

disk_full_action = HALT

If the value of the "disk_full_action" option is not "SYSLOG", "SINGLE", or "HALT", or the line is commented out, ask the system administrator (SA) to indicate how the system takes appropriate action when an audit storage volume is full. If there is no evidence of appropriate action, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to shut down by default upon audit failure (unless availability is an overriding concern).

Add or update the following line (depending on configuration "disk_full_action" can be set to "SYSLOG" or "SINGLE" depending on configuration) in "/etc/audit/auditd.conf" file:

disk_full_action = HALT

If availability has been determined to be more important, and this decision is documented with the information system security officer (ISSO), configure the operating system to notify SA staff and ISSO staff in the event of an audit processing failure by setting the "disk_full_action" to "SYSLOG".'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61895r926447_chk'
  tag severity: 'medium'
  tag gid: 'V-258154'
  tag rid: 'SV-258154r926449_rule'
  tag stig_id: 'RHEL-09-653025'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-61819r926448_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
