control 'SV-257840' do
  title 'RHEL 9 must have the nss-tools package installed.'
  desc 'Network Security Services (NSS) is a set of libraries designed to support cross-platform development of security-enabled client and server applications. Install the "nss-tools" package to install command-line tools to manipulate the NSS certificate and key database.'
  desc 'check', 'Verify that RHEL 9 has the nss-tools package installed with the following command:

$ dnf list --installed nss-tools

Example output:

nss-tools.x86_64          3.71.0-7.el9

If the "nss-tools" package is not installed, this is a finding.'
  desc 'fix', 'The nss-tools package can be installed with the following command:
 
$ sudo dnf install nss-tools'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61581r925505_chk'
  tag severity: 'medium'
  tag gid: 'V-257840'
  tag rid: 'SV-257840r925507_rule'
  tag stig_id: 'RHEL-09-215085'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61505r925506_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
