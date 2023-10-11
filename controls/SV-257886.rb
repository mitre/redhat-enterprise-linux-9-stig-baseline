control 'SV-257886' do
  title 'RHEL 9 /var/log/messages file must have mode 0640 or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 9 system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the "/var/log/messages" file has a mode of "0640" or less permissive with the following command:

$ ls -la /var/log/messages

rw-------. 1 root root 564223 July 11 11:34 /var/log/messages

If "/var/log/messages" does not have a mode of "0640" or less permissive, this is a finding.'
  desc 'fix', 'Configure the "/var/log/messages" file to have a mode of "0640" by running the following command:

$ sudo chmod 0640 /var/log/messages'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61627r925643_chk'
  tag severity: 'medium'
  tag gid: 'V-257886'
  tag rid: 'SV-257886r925645_rule'
  tag stig_id: 'RHEL-09-232030'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-61551r925644_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
