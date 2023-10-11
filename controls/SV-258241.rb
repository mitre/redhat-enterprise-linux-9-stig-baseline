control 'SV-258241' do
  title 'RHEL 9 must implement a system-wide encryption policy.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

'
  desc 'check', 'Verify that the RHEL 9 cryptography policy has been configured correctly with the following commands:

$ sudo update-crypto-policies --show 

FIPS

If the cryptography is not set to "FIPS" and is not applied, this is a finding.

$ sudo update-crypto-policies --check

The configured policy matches the generated policy

If the command does not return "The configured policy matches the generated policy", this is a finding.'
  desc 'fix', 'Configure the operating system to implement FIPS mode with the following command

$ sudo fips-mode-setup --enable

Reboot the system for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61982r926708_chk'
  tag severity: 'medium'
  tag gid: 'V-258241'
  tag rid: 'SV-258241r926710_rule'
  tag stig_id: 'RHEL-09-672045'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-61906r926709_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)', 'MA-4 (6)']
end
