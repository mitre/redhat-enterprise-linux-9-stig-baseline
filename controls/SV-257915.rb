control 'SV-257915' do
  title 'The RHEL 8 /var/log directory must be group-owned by root.'
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
  desc 'check', 'Verify the "/var/log" directory is group-owned by root with the following
command:

    $ sudo stat -c "%G" /var/log

    root

    If "root" is not returned as a result, this is a finding.'
  desc 'fix', 'Change the group of the directory "/var/log" to "root" by running the
following command:

    $ sudo chgrp root /var/log'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-230250'
  tag rid: 'SV-257915r627750_rule'
  tag stig_id: 'RHEL-08-010260'
  tag fix_id: 'F-32894r567497_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host'
  tag 'container'

  describe directory('/var/log') do
    it { should exist }
    its('group') { should eq 'root' }
  end
end
