control 'SV-258239' do
  title 'The RHEL 8 operating system must implement DoD-approved encryption in
the OpenSSL package.'
  desc 'Without cryptographic integrity protections, information can be
altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DoD nonpublic information systems by
an authorized user (or an information system) communicating through an
external, non-organization-controlled network. Remote access methods include,
for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography
enabling distribution of the public key to verify the hash information while
maintaining the confidentiality of the secret key used to generate the hash.

    RHEL 8 incorporates system-wide crypto policies by default.  The employed
algorithms can be viewed in the /etc/crypto-policies/back-ends/openssl.config
file.'
  desc 'check', 'Verify the OpenSSL library is configured to use only ciphers employing FIPS
140-2-approved algorithms:

    Verify that system-wide crypto policies are in effect:

    $ sudo grep -i opensslcnf.config /etc/pki/tls/openssl.cnf

    .include /etc/crypto-policies/back-ends/opensslcnf.config

    If the "opensslcnf.config" is not defined in the
"/etc/pki/tls/openssl.cnf" file, this is a finding.

    Verify which system-wide crypto policy is in use:

    $ sudo update-crypto-policies --show

    FIPS

    If the system-wide crypto policy is set to anything other than "FIPS",
this is a finding.'
  desc 'fix', 'Configure the RHEL 8 OpenSSL library to use only ciphers employing FIPS
140-2-approved algorithms with the following command:

    $ sudo fips-mode-setup --enable

    A reboot is required for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag gid: 'V-230254'
  tag rid: 'SV-258239r877394_rule'
  tag stig_id: 'RHEL-08-010293'
  tag fix_id: 'F-32898r567509_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  only_if("Checking the host's FIPS compliance can't be done within the container and should be reveiwed manually.") {
    !(virtualization.system.eql?('docker') && !file('/etc/pki/tls/openssl.cnf').exist?)
  }

  describe 'A line in the OpenSSL config file' do
    subject { command('grep -i opensslcnf.config /etc/pki/tls/openssl.cnf').stdout.strip }
    it { should match(/^\.include.*opensslcnf.config$/) }
  end

  describe 'System-wide crypto policy' do
    subject { command('update-crypto-policies --show').stdout.strip }
    it { should eq input('system_wide_crypto_policy') }
  end
end
