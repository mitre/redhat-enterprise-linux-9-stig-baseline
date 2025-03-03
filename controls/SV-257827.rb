control 'SV-257827' do
  title 'RHEL 9 must not have the sendmail package installed.'
  desc 'The sendmail software was not developed with security in mind, and its design prevents it from being effectively contained by SELinux. Postfix must be used instead.'
  desc 'check', 'Verify that the sendmail package is not installed with the following command:

$ sudo dnf list --installed sendmail

Error: No matching Packages to list

If the "sendmail" package is installed, this is a finding.'
  desc 'fix', 'Remove the sendmail package with the following command:

$ sudo dnf remove sendmail'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257827'
  tag rid: 'SV-257827r991589_rule'
  tag stig_id: 'RHEL-09-215020'
  tag fix_id: 'F-61492r925467_fix'
  tag cci: ['CCI-000381', 'CCI-000366']
  tag nist: ['CM-7 a', 'CM-6 b']
  tag 'host'
  tag 'container'

  describe package('sendmail') do
    it { should_not be_installed }
  end
end
