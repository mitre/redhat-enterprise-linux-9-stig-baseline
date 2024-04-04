control 'SV-258240' do
  title 'The RHEL 8 operating system must implement DoD-approved TLS encryption
in the OpenSSL package.'
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
  desc 'check', 'Verify the OpenSSL library is configured to use only DoD-approved TLS encryption:

For versions prior to crypto-policies-20210617-1.gitc776d3e.el8.noarch:

$ sudo grep -i  MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config

MinProtocol = TLSv1.2

If the "MinProtocol" is set to anything older than "TLSv1.2", this is a finding.

For version crypto-policies-20210617-1.gitc776d3e.el8.noarch and newer:

$ sudo grep -i  MinProtocol /etc/crypto-policies/back-ends/opensslcnf.config

TLS.MinProtocol = TLSv1.2
DTLS.MinProtocol = DTLSv1.2

If the "TLS.MinProtocol" is set to anything older than "TLSv1.2" or the "DTLS.MinProtocol" is set to anything older than DTLSv1.2, this is a finding.'
  desc 'fix', 'Configure the RHEL 8 OpenSSL library to use only DoD-approved TLS encryption by editing the following line in the "/etc/crypto-policies/back-ends/opensslcnf.config" file:

For versions prior to crypto-policies-20210617-1.gitc776d3e.el8.noarch:
MinProtocol = TLSv1.2

For version crypto-policies-20210617-1.gitc776d3e.el8.noarch and newer:
TLS.MinProtocol = TLSv1.2
DTLS.MinProtocol = DTLSv1.2
A reboot is required for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag gid: 'V-230255'
  tag rid: 'SV-258240r877394_rule'
  tag stig_id: 'RHEL-08-010294'
  tag fix_id: 'F-32899r809381_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container'

  crypto_policies = package('crypto-policies')

  if crypto_policies.version < '20210617-1.gitc776d3e.el8.noarch'
    describe parse_config_file('/etc/crypto-policies/back-ends/opensslcnf.config') do
      its('MinProtocol') { should be_in ['TLSv1.2', 'TLSv1.3'] }
    end
  else
    describe parse_config_file('/etc/crypto-policies/back-ends/opensslcnf.config') do
      its(['TLS.MinProtocol']) { should be_in ['TLSv1.2', 'TLSv1.3'] }
      its(['DTLS.MinProtocol']) { should be_in ['DTLSv1.2', 'DTLSv1.3'] }
    end
  end
end
