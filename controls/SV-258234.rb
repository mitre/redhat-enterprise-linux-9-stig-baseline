control 'SV-258234' do
  title 'RHEL 9 must have the crypto-policies package installed.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.'
  desc 'check', 'Verify that the RHEL 9 crypto-policies package is installed with the following command:

$ dnf list --installed crypto-policies

Example output:

crypto-policies.noarch          20240828-2.git626aa59.el9_5

If the crypto-policies package is not installed, this is a finding.'
  desc 'fix', 'Install the crypto-policies package (if the package is not already installed) with the following command:

$ sudo dnf -y install crypto-policies'
  impact 0.5
  tag check_id: 'C-61975r1051248_chk'
  tag severity: 'medium'
  tag gid: 'V-258234'
  tag rid: 'SV-258234r1051250_rule'
  tag stig_id: 'RHEL-09-215100'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-61899r1051249_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe package('crypto-policies') do
    it { should be_installed }
  end
end
