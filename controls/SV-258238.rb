control 'SV-258238' do
  title 'RHEL 9 must implement DOD-approved TLS encryption in the GnuTLS package.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Transport Layer Security (TLS) encryption is a required security setting as a number of known vulnerabilities have been reported against Secure Sockets Layer (SSL) and earlier versions of TLS. Encryption of private information is essential to ensuring data confidentiality. If private information is not encrypted, it can be intercepted and easily read by an unauthorized party. SQL Server must use a minimum of FIPS 140-3 approved TLS version 1.2, and all non-FIPS-approved SSL and TLS versions must be disabled. NIST 800-53 specifies the preferred configurations for government systems.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  desc 'check', 'Verify if GnuTLS uses defined DOD-approved TLS Crypto Policy with the following command:

 $ update-crypto-policies --show
FIPS

If the system wide crypto policy is not set to "FIPS", this is a finding.'
  desc 'fix', 'Configure the RHEL 9 GnuTLS library to use only NIST-approved encryption with the following steps to enable FIPS mode:

$ sudo fips-mode-setup --enable

A reboot is required for the changes to take effect.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000423-GPOS-00187']
  tag gid: 'V-258238'
  tag rid: 'SV-258238r926701_rule'
  tag stig_id: 'RHEL-09-672030'
  tag fix_id: 'F-61903r926700_fix'
  tag cci: ['CCI-001453', 'CCI-002418']
  tag nist: ['AC-17 (2)', 'SC-8']
  tag 'host'
  tag 'container'

  gnutls = file('/etc/crypto-policies/back-ends/gnutls.config').content.upcase.strip.split(':')
  unapproved_versions = input('unapproved_ssl_tls_versions').map(&:upcase)
  failing_versions = unapproved_versions - gnutls

  describe 'GnuTLS' do
    it 'should disable unapproved SSL/TLS versions' do
      expect(failing_versions).to be_empty, "GnuTLS should not allow:\n\t- #{failing_versions.join("\n\t- ")}"
    end
  end
end
