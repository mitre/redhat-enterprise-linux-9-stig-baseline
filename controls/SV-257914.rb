control 'SV-257914' do
  title 'RHEL 9 /var/log directory must be owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 9 system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the "/var/log" directory is owned by root with the following command:

$ ls -ld /var/log

drwxr-xr-x. 16 root root 4096 July 11 11:34 /var/log

If "/var/log" does not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure the owner of the directory "/var/log" to "root" by running the following command:

$ sudo chown root /var/log'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61655r925727_chk'
  tag severity: 'medium'
  tag gid: 'V-257914'
  tag rid: 'SV-257914r925729_rule'
  tag stig_id: 'RHEL-09-232170'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-61579r925728_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
