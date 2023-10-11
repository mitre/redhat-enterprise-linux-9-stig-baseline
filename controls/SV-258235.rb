control 'SV-258235' do
  title 'RHEL 9 crypto policy files must match files shipped with the operating system.'
  desc 'The RHEL 9 package "crypto-policies" defines the cryptography policies for the system.

If the files are changed from those shipped with the operating system, it may be possible for RHEL 9 to use cryptographic functions that are not FIPS 140-3 approved.

'
  desc 'check', 'Verify that the RHEL 9 package "crypto-policies" has not been modified with the following command:

$ rpm -V crypto-policies

If the command has any output, this is a finding.'
  desc 'fix', 'Reinstall the crypto-policies package to remove any modifications.

$ sudo dnf reinstall crypto-policies'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61976r926690_chk'
  tag severity: 'high'
  tag gid: 'V-258235'
  tag rid: 'SV-258235r926692_rule'
  tag stig_id: 'RHEL-09-672015'
  tag gtitle: 'SRG-OS-000478-GPOS-00223'
  tag fix_id: 'F-61900r926691_fix'
  tag satisfies: ['SRG-OS-000478-GPOS-00223', 'SRG-OS-000396-GPOS-00176']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
