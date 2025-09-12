control 'SV-258236' do
  title 'RHEL 9 cryptographic policy must not be overridden.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.'
  desc 'check', 'Verify that RHEL 9 cryptographic policies are not overridden.

Verify that the configured policy matches the generated policy with the following command:

$ sudo update-crypto-policies --check && echo PASS

The configured policy matches the generated policy
PASS

If the last line is not "PASS", this is a finding.

List all of the crypto backends configured on the system with the following command:

$ ls -l /etc/crypto-policies/back-ends/

lrwxrwxrwx. 1 root root  40 Nov 13 16:29 bind.config -> /usr/share/crypto-policies/FIPS/bind.txt
lrwxrwxrwx. 1 root root  42 Nov 13 16:29 gnutls.config -> /usr/share/crypto-policies/FIPS/gnutls.txt
lrwxrwxrwx. 1 root root  40 Nov 13 16:29 java.config -> /usr/share/crypto-policies/FIPS/java.txt
lrwxrwxrwx. 1 root root  46 Nov 13 16:29 javasystem.config -> /usr/share/crypto-policies/FIPS/javasystem.txt
lrwxrwxrwx. 1 root root  40 Nov 13 16:29 krb5.config -> /usr/share/crypto-policies/FIPS/krb5.txt
lrwxrwxrwx. 1 root root  45 Nov 13 16:29 libreswan.config -> /usr/share/crypto-policies/FIPS/libreswan.txt
lrwxrwxrwx. 1 root root  42 Nov 13 16:29 libssh.config -> /usr/share/crypto-policies/FIPS/libssh.txt
-rw-r--r--. 1 root root 398 Nov 13 16:29 nss.config
lrwxrwxrwx. 1 root root  43 Nov 13 16:29 openssh.config -> /usr/share/crypto-policies/FIPS/openssh.txt
lrwxrwxrwx. 1 root root  49 Nov 13 16:29 opensshserver.config -> /usr/share/crypto-policies/FIPS/opensshserver.txt
lrwxrwxrwx. 1 root root  46 Nov 13 16:29 opensslcnf.config -> /usr/share/crypto-policies/FIPS/opensslcnf.txt
lrwxrwxrwx. 1 root root  43 Nov 13 16:29 openssl.config -> /usr/share/crypto-policies/FIPS/openssl.txt
lrwxrwxrwx. 1 root root  48 Nov 13 16:29 openssl_fips.config -> /usr/share/crypto-policies/FIPS/openssl_fips.txt

If the paths do not point to the respective files under /usr/share/crypto-policies/FIPS path, this is a finding.
Note: nss.config should not be hyperlinked.'
  desc 'fix', 'Configure RHEL 9 to correctly implement the systemwide cryptographic policies by reinstalling the crypto-policies package contents.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.7
  tag check_id: 'C-61977r1051251_chk'
  tag severity: 'high'
  tag gid: 'V-258236'
  tag rid: 'SV-258236r1051253_rule'
  tag stig_id: 'RHEL-09-672020'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-61901r1051252_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  crypto_policies_dir = '/etc/crypto-policies/back-ends'
  expected_link_path_dir = '/usr/share/crypto-policies/FIPS'

  crypto_policies = command("ls -l #{crypto_policies_dir} | awk '{ print $9 }'").stdout.strip.split("\n")

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

  output = command('update-crypto-policies --check 2>&1 && echo PASS').stdout.strip
  last_line = output.lines.map(&:strip).reject(&:empty?).last.to_s

  describe 'System cryptographic policy must match the generated policy' do
    subject { last_line }
    it { should cmp 'PASS' }
  end
end
