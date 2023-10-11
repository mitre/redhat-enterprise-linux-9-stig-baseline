control 'SV-258227' do
  title 'RHEL 9 must take appropriate action when a critical audit processing failure occurs.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

'
  desc 'check', 'Verify the audit service is configured to panic on a critical error with the following command:

$ sudo grep "\\-f" /etc/audit/audit.rules 

-f 2

If the value for "-f" is not "2", and availability is not documented as an overriding concern, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to shut down when auditing failures occur.

Add the following line to the bottom of the /etc/audit/audit.rules file:

-f 2'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61968r926666_chk'
  tag severity: 'medium'
  tag gid: 'V-258227'
  tag rid: 'SV-258227r926668_rule'
  tag stig_id: 'RHEL-09-654265'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-61892r926667_fix'
  tag satisfies: ['SRG-OS-000046-GPOS-00022', 'SRG-OS-000047-GPOS-00023']
  tag 'documentable'
  tag cci: ['CCI-000139', 'CCI-000140']
  tag nist: ['AU-5 a', 'AU-5 b']
end
