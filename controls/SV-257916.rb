control 'SV-257916' do
  title 'RHEL 9 /var/log/messages file must be owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 9 system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the "/var/log/messages" file is owned by root with the following command:
	
$ stat -c "%U %n" /var/log/messages
	
root /var/log
	
If "/var/log/messages" does not have an owner of "root", this is a finding.'
  desc 'fix', 'Change the owner of the "/var/log/messages" file to "root" by running the following command:

$ sudo chown root /var/log/messages'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-257916'
  tag rid: 'SV-257916r1044973_rule'
  tag stig_id: 'RHEL-09-232180'
  tag fix_id: 'F-61581r925734_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe.one do
    describe file('/var/log/messages') do
      it { should be_owned_by 'root' }
    end
    describe file('/var/log/messages') do
      it { should_not exist }
    end
  end
end
