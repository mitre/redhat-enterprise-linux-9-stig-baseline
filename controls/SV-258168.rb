control 'SV-258168' do
  title 'RHEL 9 must periodically flush audit records to disk to prevent the loss of audit records.'
  desc 'If option "freq" is not set to a value that requires audit records being written to disk after a threshold number is reached, then audit records may be lost.'
  desc 'check', %q(Verify that audit system is configured to flush to disk after every 100 records with the following command:

$ sudo grep freq /etc/audit/auditd.conf

freq = 100

If "freq" isn't set to a value between "1" and "100", the value is missing, or the line is commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to flush audit to disk by adding or updating the following rule in "/etc/audit/auditd.conf":

freq = 100

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag check_id: 'C-61909r943022_chk'
  tag severity: 'medium'
  tag gid: 'V-258168'
  tag rid: 'SV-258168r958428_rule'
  tag stig_id: 'RHEL-09-653095'
  tag gtitle: 'SRG-OS-000051-GPOS-00024'
  tag fix_id: 'F-61833r943023_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  freq = input('audit_flush_threshold')

  describe auditd_conf do
    its('freq.to_i') { should cmp >= freq }
  end
end
