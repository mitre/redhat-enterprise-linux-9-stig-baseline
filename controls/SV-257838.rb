control 'SV-257838' do
  title 'RHEL 9 must have the openssl-pkcs11 package installed.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. A privileged account is defined as an information system account with authorizations of a privileged user. The DOD CAC with DOD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'Verify that RHEL 9 has the openssl-pkcs11 package installed with the following command:

$ sudo dnf list --installed openssl-pkcs11

Example output:

openssl-pkcs.i686          0.4.11-7.el9
openssl-pkcs.x86_64          0.4.11-7.el9

If the "openssl-pkcs11" package is not installed, this is a finding.'
  desc 'fix', 'The openssl-pkcs11 package can be installed with the following command:

$ sudo dnf install openssl-pkcs11'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61579r925499_chk'
  tag severity: 'medium'
  tag gid: 'V-257838'
  tag rid: 'SV-257838r925501_rule'
  tag stig_id: 'RHEL-09-215075'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-61503r925500_fix'
  tag satisfies: %w(SRG-OS-000105-GPOS-00052 SRG-OS-000375-GPOS-00160 SRG-OS-000376-GPOS-00161 SRG-OS-000377-GPOS-00162)
  tag 'documentable'
  tag cci: %w(CCI-000765 CCI-001948 CCI-001953 CCI-001954)
  tag nist: ['IA-2 (1)', 'IA-2 (11)', 'IA-2 (12)', 'IA-2 (12)']

  mfa_pkg_list = %w(openssl-pkcs11)

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  elsif input('smart_card_status').eql?('disabled')
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement, this control is Not Applicable.'
    end
  else
    mfa_pkg_list.each do |pkg|
      describe package(pkg) do
        it { should be_installed }
      end
    end
  end
end
