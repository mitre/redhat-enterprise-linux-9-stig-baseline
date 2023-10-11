control 'SV-258230' do
  title 'RHEL 9 must enable FIPS mode.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated. This includes NIST FIPS-validated cryptography for the following: Provisioning digital signatures, generating cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

'
  desc 'check', 'Verify that RHEL 9 is in FIPS mode with the following command:

$ sudo fips-mode-setup --check

FIPS mode is enabled.

If FIPS mode is not enabled, this is a finding.'
  desc 'fix', 'Configure the operating system to implement FIPS mode with the following command

$ sudo fips-mode-setup --enable

Reboot the system for the changes to take effect.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61971r926675_chk'
  tag severity: 'high'
  tag gid: 'V-258230'
  tag rid: 'SV-258230r926677_rule'
  tag stig_id: 'RHEL-09-671010'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-61895r926676_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000877', 'CCI-002418', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'MA-4 c', 'SC-8', 'SC-13 b']
end
