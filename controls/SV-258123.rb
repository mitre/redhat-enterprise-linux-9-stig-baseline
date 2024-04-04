control 'SV-258123' do
  title 'RHEL 8 must implement certificate status checking for multifactor authentication.'
  desc 'Using an authentication device, such as a DoD Common Access Card (CAC)
    or token that is separate from the information system, ensures that even if the
    information system is compromised, credentials stored on the authentication
    device will not be affected.

    Multifactor solutions that require devices separate from information
    systems gaining access include, for example, hardware tokens providing
    time-based or challenge-response authenticators and smart cards such as the
    U.S. Government Personal Identity Verification (PIV) card and the DoD CAC.

    RHEL 8 includes multiple options for configuring certificate status
checking, but for this requirement focuses on the System Security Services
Daemon (SSSD). By default, sssd performs Online Certificate Status Protocol
(OCSP) checking and certificate verification using a sha256 digest function.'
  desc 'check', 'Verify the operating system implements certificate status checking for multifactor authentication.

Note: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Check to see if Online Certificate Status Protocol (OCSP) is enabled and using the proper digest value on the system with the following command:

$ sudo grep certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf | grep -v "^#"

certificate_verification = ocsp_dgst=sha1

If the certificate_verification line is missing from the [sssd] section, or is missing "ocsp_dgst=sha1", ask the administrator to indicate what type of multifactor authentication is being utilized and how the system implements certificate status checking.  If there is no evidence of certificate status checking being used, this is a finding.'
  desc 'fix', 'Configure the operating system to implement certificate status checking for multifactor authentication.

Review the "/etc/sssd/sssd.conf" file to determine if the system is configured to prevent OCSP or certificate verification.

Add the following line to the [sssd] section of the "/etc/sssd/sssd.conf" file:

certificate_verification = ocsp_dgst=sha1

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

$ sudo systemctl restart sssd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000377-GPOS-00162']
  tag gid: 'V-230274'
  tag rid: 'SV-258123r858741_rule'
  tag stig_id: 'RHEL-08-010400'
  tag fix_id: 'F-32918r809280_fix'
  tag cci: ['CCI-001948']
  tag nist: ['IA-2 (11)']
  tag 'host'

  only_if('This requirement is Not Applicable inside the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternate_mfa_method').nil?
    describe 'Manual Review' do
      skip "Alternate MFA method selected:\t\nConsult with ISSO to determine that alternate MFA method is approved; manually review system to ensure alternate MFA method is functioning"
    end
  else
    sssd_conf_files = input('sssd_conf_files')
    sssd_conf_contents = ini({ command: "cat #{input('sssd_conf_files').join(' ')}" })
    sssd_certificate_verification = input('sssd_certificate_verification')

    describe 'SSSD' do
      it 'should be installed and enabled' do
        expect(service('sssd')).to be_installed.and be_enabled
        expect(sssd_conf_contents.params).to_not be_empty, "SSSD configuration files not found or have no content; files checked:\n\t- #{sssd_conf_files.join("\n\t- ")}"
      end
      if sssd_conf_contents.params.nil?
        it "should configure certificate_verification to be '#{sssd_certificate_verification}'" do
          expect(sssd_conf_contents.sssd.certificate_verification).to eq(sssd_certificate_verification)
        end
      end
    end
  end
end
