control 'SV-258236' do
  title 'RHEL 9 crypto policy must not be overridden.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

'
  desc 'check', 'Verify that RHEL 9 custom crypto policies are loaded correctly.

List all of the crypto backends configured on the system.

$ ls -l /etc/crypto-policies/back-ends/
lrwxrwxrwx. 1 root root 40 Oct  7 08:44 bind.config -> /usr/share/crypto-policies/FIPS/bind.txt
lrwxrwxrwx. 1 root root 42 Oct  7 08:44 gnutls.config -> /usr/share/crypto-policies/FIPS/gnutls.txt
lrwxrwxrwx. 1 root root 40 Oct  7 08:44 java.config -> /usr/share/crypto-policies/FIPS/java.txt
lrwxrwxrwx. 1 root root 46 Oct  7 08:44 javasystem.config -> /usr/share/crypto-policies/FIPS/javasystem.txt
lrwxrwxrwx. 1 root root 40 Oct  7 08:44 krb5.config -> /usr/share/crypto-policies/FIPS/krb5.txt
lrwxrwxrwx. 1 root root 45 Oct  7 08:44 libreswan.config -> /usr/share/crypto-policies/FIPS/libreswan.txt
lrwxrwxrwx. 1 root root 42 Oct  7 08:44 libssh.config -> /usr/share/crypto-policies/FIPS/libssh.txt
lrwxrwxrwx. 1 root root 39 Oct  7 08:44 nss.config -> /usr/share/crypto-policies/FIPS/nss.txt
lrwxrwxrwx. 1 root root 43 Oct  7 08:44 openssh.config -> /usr/share/crypto-policies/FIPS/openssh.txt
lrwxrwxrwx. 1 root root 49 Oct  7 08:44 opensshserver.config -> /usr/share/crypto-policies/FIPS/opensshserver.txt
lrwxrwxrwx. 1 root root 46 Oct  7 08:44 opensslcnf.config -> /usr/share/crypto-policies/FIPS/opensslcnf.txt
lrwxrwxrwx. 1 root root 43 Oct  7 08:44 openssl.config -> /usr/share/crypto-policies/FIPS/openssl.txt

If the paths do not point the respective files under /usr/share/crypto-policies/FIPS path, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to FIPS crypto policy.

$ sudo ln -s /usr/share/crypto-policies/FIPS/<service>.txt /etc/crypto-policies/back-ends/<service>.conf

Replace <service> with every service that is not set to FIPS.

The system must be rebooted to make the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61977r926693_chk'
  tag severity: 'medium'
  tag gid: 'V-258236'
  tag rid: 'SV-258236r926695_rule'
  tag stig_id: 'RHEL-09-672020'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-61901r926694_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)', 'MA-4 (6)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('use_fips') == false
    impact 0.0
    describe 'This control is Not Applicable as FIPS is not required for this system' do
      skip 'This control is Not Applicable as FIPS is not required for this system'
    end
  else
    
    crypto_policies_dir = '/etc/crypto-policies/back-ends'
    expected_link_path_dir = '/usr/share/crypto-policies/FIPS'
  
    crypto_policies = command("ls -l #{crypto_policies_dir} | awk \'{ print $9 }\'").stdout.strip.split("\n")
  
    failing_crypto_policies = {}
  
    crypto_policies.each do |crypto_policy|
      service = "#{crypto_policies_dir}/#{crypto_policy}"
      link_path = file(service).link_path
  
      if link_path.nil?
        failing_crypto_policies[service] = 'No link path found'
      elsif !link_path.match?(/^#{expected_link_path_dir}/)
        failing_crypto_policies[service] = link_path
      end
    end

    describe 'Crypto policies' do
      it 'should link to the correct libriries' do
        expect(failing_crypto_policies).to be_empty, "Failing crypto policies:\n\t- #{failing_crypto_policies}"
      end
    end
  end
end
