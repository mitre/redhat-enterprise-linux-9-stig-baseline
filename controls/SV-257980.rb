control 'SV-257980' do
  title 'RHEL 9 must have the openssh-clients package installed.'
  desc 'This package includes utilities to make encrypted connections and transfer files securely to SSH servers.'
  desc 'check', 'Verify that RHEL 9 has the openssh-clients package installed with the following command:

$ sudo dnf list --installed openssh-clients

Example output:

openssh-clients.x86_64          8.7p1-8.el9

If the "openssh-clients" package is not installed, this is a finding.'
  desc 'fix', 'The openssh-clients package can be installed with the following command:
 
$ sudo dnf install openssh-clients'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61721r925925_chk'
  tag severity: 'medium'
  tag gid: 'V-257980'
  tag rid: 'SV-257980r928960_rule'
  tag stig_id: 'RHEL-09-255020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61645r928960_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
