control 'SV-258234' do
  title 'RHEL 9 must have the crypto-policies package installed.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

'
  desc 'check', 'Verify that RHEL 9 crypto-policies package is installed with the following command:

$ sudo dnf list --installed crypto-policies

Example output:

crypto-policies.noarch          20220223-1.git5203b41.el9_0.1

If the "crypto-policies" package is not installed, this is a finding.'
  desc 'fix', 'Install the crypto-policies package (if the package is not already installed) with the following command:

$ sudo dnf install crypto-policies'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61975r926687_chk'
  tag severity: 'medium'
  tag gid: 'V-258234'
  tag rid: 'SV-258234r926689_rule'
  tag stig_id: 'RHEL-09-672010'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-61899r926688_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)', 'MA-4 (6)']
end
