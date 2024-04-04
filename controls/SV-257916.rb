control 'SV-257916' do
  title 'The RHEL 8 /var/log/messages file must be owned by root.'
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
  desc 'check', 'Verify that the /var/log/messages file is owned by root with the following
command:

    $ sudo stat -c "%U" /var/log/messages

    root

    If "root" is not returned as a result, this is a finding.'
  desc 'fix', 'Change the owner of the file /var/log/messages to root by running the
following command:

    $ sudo chown root /var/log/messages'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-230246'
  tag rid: 'SV-257916r627750_rule'
  tag stig_id: 'RHEL-08-010220'
  tag fix_id: 'F-32890r567485_fix'
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
