control 'SV-258083' do
  title 'RHEL 9 must have the sudo package installed.'
  desc '"sudo" is a program designed to allow a system administrator to give limited root privileges to users and log root activity. The basic philosophy is to give as few privileges as possible but still allow system users to get their work done.'
  desc 'check', 'Verify that RHEL 9 sudo package is installed with the following command:

$ sudo dnf list --installed sudo

Example output:

sudo.x86_64          1.9.5p2-7.el9

If the "sudo" package is not installed, this is a finding.'
  desc 'fix', 'The  sudo  package can be installed with the following command:
 
$ sudo dnf install sudo'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61824r926234_chk'
  tag severity: 'medium'
  tag gid: 'V-258083'
  tag rid: 'SV-258083r926236_rule'
  tag stig_id: 'RHEL-09-432010'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-61748r926235_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
