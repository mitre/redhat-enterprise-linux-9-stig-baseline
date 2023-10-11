control 'SV-257954' do
  title 'RHEL 9 libreswan package must be installed.'
  desc 'Providing the ability for remote users or systems to initiate a secure VPN connection protects information when it is transmitted over a wide area network.

'
  desc 'check', 'Verify that RHEL 9 libreswan service package is installed.

Check that the libreswan service package is installed with the following command:

$ sudo dnf list --installed libreswan

Example output:

libreswan.x86_64          4.6-3.el9

If the "libreswan" package is not installed, this is a finding.'
  desc 'fix', 'Install the libreswan service (if it is not already installed) with the following command:

$ sudo dnf install libreswan'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61695r925847_chk'
  tag severity: 'medium'
  tag gid: 'V-257954'
  tag rid: 'SV-257954r925849_rule'
  tag stig_id: 'RHEL-09-252065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61619r925848_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000803']
  tag nist: ['CM-6 b', 'IA-7']
end
