control 'SV-258170' do
  title 'RHEL 9 must write audit records to disk.'
  desc 'Audit data should be synchronously written to disk to ensure log integrity. This setting assures that all audit event data is written disk.'
  desc 'check', 'Verify that the audit system is configured to write logs to the disk with the following command:

$ sudo grep write_logs /etc/audit/auditd.conf 

write_logs = yes 

If "write_logs" does not have a value of "yes", the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Configure the audit system to write log files to the disk.

Edit the /etc/audit/auditd.conf file and add or update the "write_logs" option to "yes":

write_logs = yes 

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61911r926495_chk'
  tag severity: 'medium'
  tag gid: 'V-258170'
  tag rid: 'SV-258170r926497_rule'
  tag stig_id: 'RHEL-09-653105'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61835r926496_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
