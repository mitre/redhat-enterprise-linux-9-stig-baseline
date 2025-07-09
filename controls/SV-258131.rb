control 'SV-258131' do
  title 'RHEL 9, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a certification authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', 'Verify RHEL 9 for PKI-based authentication has valid certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Check that the system has a valid DOD root CA installed with the following command:

$ sudo openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem

Example output:

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
        Validity
        Not Before: Mar 20 18:46:41 2012 GMT
        Not After: Dec 30 18:46:41 2029 GMT
        Subject: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption

If the root CA file is not a DOD-issued certificate with a valid date and installed in the "/etc/sssd/pki/sssd_auth_ca_db.pem" location, this is a finding.'
  desc 'fix', 'Configure RHEL 9, for PKI-based authentication, to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Obtain a valid copy of the DOD root CA file from the PKI CA certificate bundle from cyber.mil and copy the DoD_PKE_CA_chain.pem into the following file:
/etc/sssd/pki/sssd_auth_ca_db.pem'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000384-GPOS-00167']
  tag gid: 'V-258131'
  tag rid: 'SV-258131r1015125_rule'
  tag stig_id: 'RHEL-09-631010'
  tag fix_id: 'F-61796r997112_fix'
  tag cci: ['CCI-000185', 'CCI-001991', 'CCI-004068']
  tag nist: ['IA-5 (2) (a)', 'IA-5 (2) (b) (1)', 'IA-5 (2) (d)', 'IA-5 (2) (b) (2)']
  tag 'host'
  tag 'container'

  only_if('If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.', impact: 0.0) {
    !input('smart_card_enabled')
  }

  root_ca_file = input('root_ca_file') # This gets the entire hash from input
  root_ca_file_path = root_ca_file['path'] # Extract the path for file operations
  issuer_dn_expected = root_ca_file['issuer_dn'] # Extract the expected issuer DN
  subject_dn_expected = root_ca_file['subject_dn'] # Extract the expected subject DN
  # quick check to see if the designated Root CA is present; fail if it is not
  if file(root_ca_file_path).exist?
    # Check the Root CA's validity and details

    describe 'The Root CA' do
      subject { x509_certificate(root_ca_file_path) }

      # Verify that the issuer_dn matches the expected issuer DN
      it 'has the correct issuer_dn' do
        expect(subject.issuer_dn).to match(issuer_dn_expected) # Match the expected issuer DN
      end

      # Verify that the subject_dn matches the expected subject DN
      it 'has the correct subject_dn' do
        expect(subject.subject_dn).to match(subject_dn_expected) # Match the expected subject DN
      end

      # Ensure that the certificate is valid (i.e., it hasn't expired)
      it 'has not expired' do
        expect(subject.validity_in_days).to be > 0
      end
    end
  else

    describe file(root_ca_file_path) do
      it { should exist }
    end

  end
end
