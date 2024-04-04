control 'SV-257914' do
  title 'The RHEL 8 /var/log directory must be owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the RHEL 8 system or platform. Additionally, Personally
Identifiable Information (PII) and operational information must not be revealed
through error messages to unauthorized personnel or their designated
representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements."
  desc 'check', 'Verify the /var/log directory is owned by root with the following command:

$ sudo stat -c "%U" /var/log

root

If "root" is not returned as a result, this is a finding.'
  desc 'fix', 'Change the owner of the directory /var/log to root by running the following
command:

    $ sudo chown root /var/log'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-230249'
  tag rid: 'SV-257914r627750_rule'
  tag stig_id: 'RHEL-08-010250'
  tag fix_id: 'F-32893r567494_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'
  tag 'container'

  describe directory('/var/log') do
    it { should exist }
    it { should be_owned_by 'root' }
  end
end
