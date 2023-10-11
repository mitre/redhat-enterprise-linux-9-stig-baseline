control 'SV-257885' do
  title 'RHEL 9 /var/log directory must have mode 0755 or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 9 system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that the "/var/log" directory has a mode of "0755" or less permissive with the following command:

$ ls -ld /var/log

drwxr-xr-x. 16 root root 4096 July 11 11:34 /var/log

If "/var/log" does not have a mode of "0755" or less permissive, this is a finding.'
  desc 'fix', 'Configure the "/var/log" directory to a mode of "0755" by running the following command:

$ sudo chmod 0755 /var/log'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61626r925640_chk'
  tag severity: 'medium'
  tag gid: 'V-257885'
  tag rid: 'SV-257885r925642_rule'
  tag stig_id: 'RHEL-09-232025'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-61550r925641_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
