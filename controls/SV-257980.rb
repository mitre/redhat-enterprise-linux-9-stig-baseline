control 'SV-257980' do
  title 'RHEL 9 must have the openssh-clients package installed.'
  desc 'This package includes utilities to make encrypted connections and transfer files securely to SSH servers.'
  desc 'check', 'Verify that RHEL 9 has the openssh-clients package installed with the following command:

$ dnf list --installed openssh-clients

Example output:

openssh-clients.x86_64          8.7p1-8.el9

If the "openssh-clients" package is not installed, this is a finding.'
  desc 'fix', 'The openssh-clients package can be installed with the following command:

$ sudo dnf install openssh-clients'
  impact 0.5
  tag check_id: 'C-61721r1045014_chk'
  tag severity: 'medium'
  tag gid: 'V-257980'
  tag rid: 'SV-257980r1045016_rule'
  tag stig_id: 'RHEL-09-255020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61645r1045015_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe package('openssh-clients') do
    it { should be_installed }
  end
end
