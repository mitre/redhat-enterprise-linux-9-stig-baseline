control 'SV-257827' do
  title 'RHEL 9 must not have the sendmail package installed.'
  desc 'The sendmail software was not developed with security in mind, and its design prevents it from being effectively contained by SELinux. Postfix must be used instead.

'
  desc 'check', 'Verify that the sendmail package is not installed with the following command:

$ sudo dnf list --installed sendmail

Error: No matching Packages to list

If the "sendmail" package is installed, this is a finding.'
  desc 'fix', 'Remove the sendmail package with the following command:

$ sudo dnf remove sendmail'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61568r925466_chk'
  tag severity: 'medium'
  tag gid: 'V-257827'
  tag rid: 'SV-257827r925468_rule'
  tag stig_id: 'RHEL-09-215020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61492r925467_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000095-GPOS-00049']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
end
