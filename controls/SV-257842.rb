control 'SV-257842' do
  title 'RHEL 9 must have the s-nail package installed.'
  desc 'The "s-nail" package provides the mail command required to allow sending email notifications of unauthorized configuration changes to designated personnel.'
  desc 'check', 'Verify that RHEL 9 is configured to allow sending email notifications.

Note: The "s-nail" package provides the "mail" command that is used to send email messages.

Verify that the "s-nail" package is installed on the system:

$ sudo dnf list --installed mailx

s-nail.x86_64          14.9.22-6.el9
	 
If "s-nail" package is not installed, this is a finding.'
  desc 'fix', 'The s-nail package can be installed with the following command:

$ sudo dnf install s-nail'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61583r925511_chk'
  tag severity: 'medium'
  tag gid: 'V-257842'
  tag rid: 'SV-257842r925513_rule'
  tag stig_id: 'RHEL-09-215095'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-61507r925512_fix'
  tag 'documentable'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
