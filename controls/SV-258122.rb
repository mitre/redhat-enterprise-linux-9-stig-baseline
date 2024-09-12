control 'SV-258122' do
  title 'RHEL 9 must enable certificate based smart card authentication.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. A privileged account is defined as an information system account with authorizations of a privileged user. The DOD Common Access Card (CAC) with DOD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify that RHEL 9 has smart cards are enabled in System Security Services Daemon (SSSD), run the following command:

$ sudo grep pam_cert_auth /etc/sssd/sssd.conf

pam_cert_auth = True

If "pam_cert_auth" is not set to "True", the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Edit the file "/etc/sssd/sssd.conf" and add or edit the following line:

pam_cert_auth = True'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000375-GPOS-00160']
  tag gid: 'V-258122'
  tag rid: 'SV-258122r997106_rule'
  tag stig_id: 'RHEL-09-611165'
  tag fix_id: 'F-61787r926352_fix'
  tag cci: ['CCI-000765', 'CCI-001948', 'CCI-004046', 'CCI-004047']
  tag nist: ['IA-2 (1)', 'IA-2 (11)', 'IA-2 (6) (a)', 'IA-2 (6) (b)']
  tag 'host'

  only_if('If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.', impact: 0.0) {
    input('smart_card_enabled')
  }

  sssd_conf_files = input('sssd_conf_files')
  sssd_conf_contents = ini({ command: "cat #{input('sssd_conf_files').join(' ')}" })

  pam_auth_files = input('pam_auth_files')

  describe 'SSSD' do
    it 'should be installed and enabled' do
      expect(service('sssd')).to be_installed.and be_enabled
      expect(sssd_conf_contents.params).to_not be_empty, "SSSD configuration files not found or have no content; files checked:\n\t- #{sssd_conf_files.join("\n\t- ")}"
    end
    if sssd_conf_contents.params.nil?
      it 'should configure pam_cert_auth' do
        expect(sssd_conf_contents.sssd.pam_cert_auth).to eq(true)
      end
    end
  end

  [pam_auth_files['system-auth'], pam_auth_files['smartcard-auth']].each do |path|
    describe pam(path) do
      its('lines') { should match_pam_rule('.* .* pam_sss.so (try_cert_auth|require_cert_auth)') }
    end
  end
end
