control 'SV-257916' do
  title 'RHEL 9 /var/log/messages file must be owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 9 system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the "/var/log/messages" file is owned by root with the following command:

$ ls -la /var/log/messages

rw-------. 1 root root 564223 July 11 11:34 /var/log/messages

If "/var/log/messages" does not have an owner of "root", this is a finding.'
  desc 'fix', 'Change the owner of the "/var/log/messages" file to "root" by running the following command:

$ sudo chown root /var/log/messages'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61657r925733_chk'
  tag severity: 'medium'
  tag gid: 'V-257916'
  tag rid: 'SV-257916r925735_rule'
  tag stig_id: 'RHEL-09-232180'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-61581r925734_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
