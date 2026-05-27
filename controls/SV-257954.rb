control 'SV-257954' do
  title 'RHEL 9 libreswan package must be installed.'
  desc 'Providing the ability for remote users or systems to initiate a secure VPN connection protects information when it is transmitted over a wide area network.'
  desc 'check', 'Note: If there is no operational need for Libreswan to be installed, this rule is not applicable.

Verify that RHEL 9 libreswan service package is installed.

Check that the libreswan service package is installed with the following command:

$ dnf list --installed libreswan

Example output:

libreswan.x86_64          4.6-3.el9

If the "libreswan" package is not installed, this is a finding.'
  desc 'fix', 'Install the libreswan service (if it is not already installed) with the following command:

$ sudo dnf install libreswan'
  impact 0.5
  tag check_id: 'C-61695r1101930_chk'
  tag severity: 'medium'
  tag gid: 'V-257954'
  tag rid: 'SV-257954r1106315_rule'
  tag stig_id: 'RHEL-09-252065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61619r925848_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000803']
  tag nist: ['CM-6 b', 'IA-7']
  tag 'host'
  tag 'container'

  if input('libreswan_required')
    describe package('libreswan') do
      it { should be_installed }
    end
  else
    impact 0.0
    describe 'N/A' do
      skip 'If there is no operational need for Libreswan to be installed, this rule is not applicable.'
    end
  end
end
