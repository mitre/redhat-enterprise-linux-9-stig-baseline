control 'SV-258122' do
  title 'RHEL 8 must implement smart card logon for multifactor authentication
for access to interactive accounts.'
  desc 'Using an authentication device, such as a Common Access Card (CAC) or
token that is separate from the information system, ensures that even if the
information system is compromised, that compromise will not affect credentials
stored on the authentication device.

    Multifactor solutions that require devices separate from information
systems gaining access include, for example, hardware tokens providing
time-based or challenge-response authenticators and smart cards such as the
U.S. Government Personal Identity Verification card and the DoD CAC.

    There are various methods of implementing multifactor authentication for
RHEL 8. Some methods include a local system multifactor account mapping or
joining the system to a domain and utilizing a Red Hat idM server or Microsoft
Windows Active Directory server. Any of these methods will require that the
client operating system handle the multifactor authentication correctly.'
  desc 'check', 'Verify RHEL 8 uses multifactor authentication for local access to accounts.

Note: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Check that the "pam_cert_auth" setting is set to "true" in the "/etc/sssd/sssd.conf" file.

Check that the "try_cert_auth" or "require_cert_auth" options are configured in both "/etc/pam.d/system-auth" and "/etc/pam.d/smartcard-auth" files with the following command:

     $ sudo grep -ir cert_auth /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf /etc/pam.d/*
     /etc/sssd/sssd.conf:pam_cert_auth = True
     /etc/pam.d/smartcard-auth:auth   sufficient   pam_sss.so try_cert_auth
     /etc/pam.d/system-auth:auth   [success=done authinfo_unavail=ignore ignore=ignore default=die]   pam_sss.so try_cert_auth

If "pam_cert_auth" is not set to "true" in "/etc/sssd/sssd.conf", this is a finding.

If "pam_sss.so" is not set to "try_cert_auth" or "require_cert_auth" in both the "/etc/pam.d/smartcard-auth" and "/etc/pam.d/system-auth" files, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to use multifactor authentication for local access to
accounts.

    Add or update the "pam_cert_auth" setting in the "/etc/sssd/sssd.conf"
file to match the following line:

    [pam]
    pam_cert_auth = True

    Add or update "pam_sss.so" with "try_cert_auth" or
"require_cert_auth" in the "/etc/pam.d/system-auth" and
"/etc/pam.d/smartcard-auth" files based on the following examples:

    /etc/pam.d/smartcard-auth:auth   sufficient   pam_sss.so try_cert_auth

    /etc/pam.d/system-auth:auth   [success=done authinfo_unavail=ignore
ignore=ignore default=die]   pam_sss.so try_cert_auth

    The "sssd" service must be restarted for the changes to take effect. To
restart the "sssd" service, run the following command:

    $ sudo systemctl restart sssd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag gid: 'V-230372'
  tag rid: 'SV-258122r942945_rule'
  tag stig_id: 'RHEL-08-020250'
  tag fix_id: 'F-33016r942944_fix'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
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
