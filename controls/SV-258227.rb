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

Add the following line to the bottom of the /etc/audit/rules.d/audit.rules file:

-f 2'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61968r926666_chk'
  tag severity: 'medium'
  tag gid: 'V-258227'
  tag rid: 'SV-258227r1014992_rule'
  tag stig_id: 'RHEL-09-654265'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-61892r1014991_fix'
  tag satisfies: ['SRG-OS-000046-GPOS-00022', 'SRG-OS-000047-GPOS-00023']
  tag 'documentable'
  tag cci: ['CCI-000139', 'CCI-000140']
  tag nist: ['AU-5 a', 'AU-5 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  expected_panic_value = input('expected_panic_value')
  panic_flag = command('grep "\\-f" /etc/audit/audit.rules').stdout.strip

  if input('high_availability_required')
    impact 0.0
    describe 'N/A' do
      skip 'This system is indicated as requiring high availability and cannot panic in the event of audit failure'
    end
  elsif panic_flag.empty?
    describe 'The audit service' do
      it 'is expected to configure fail behavior' do
        expect(panic_flag).not_to be_empty, "The '-f' flag was not set in audit.rules"
      end
    end
  else
    value = panic_flag.split[1].to_i
    describe 'The audit service ' do
      it 'is expected to panic on a critical error' do
        expect(value).to eq(expected_panic_value), "The '-f' flag was set to '#{value}' instead of '#{expected_panic_value}'"
      end
    end
  end
end
