control 'SV-257991' do
  title 'The RHEL 8 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-2 validated cryptographic hash algorithms.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection. Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash. RHEL 8 incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file. The system will attempt to use the first hash presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest hash available to secure the SSH connection.'
  desc 'check', 'Verify the SSH server is configured to use only MACs employing FIPS 140-2-approved algorithms with the following command:

    $ sudo grep -i macs /etc/crypto-policies/back-ends/opensshserver.config

    -oMACS=hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

If the MACs entries in the "opensshserver.config" file have any hashes other than shown here, the order differs from the example above, or they are missing or commented out, this is a finding.'
  desc 'fix', 'Configure the RHEL 8 SSH server to use only MACs employing FIPS 140-2-approved algorithms by updating the "/etc/crypto-policies/back-ends/opensshserver.config" file with the following line:

    -oMACS=hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

    A reboot is required for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag gid: 'V-230251'
  tag rid: 'SV-25799r917870_rule'
  tag stig_id: 'RHEL-08-010290'
  tag fix_id: 'F-32895r917869_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  # Check if SSH is installed within containerized RHEL
  only_if('SSH is not installed within containerized RHEL. Therefore, this requirement is not applicable.', impact: 0.0) do
    !(virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?)
  end

  # Define the required algorithms
  required_algorithms = input('openssh_server_required_algorithms')

  # TODO: make a simple resource for this based off 'login_defs' or 'yum' as a model

  # Parse the configuration file to get the value of "CRYPTO_POLICY"
  crypto_policy = parse_config_file('/etc/crypto-policies/back-ends/opensshserver.config')['CRYPTO_POLICY']

  # Parse the CRYPTO_POLICY string into a hash of configuration options
  config_options = crypto_policy.scan(/-o(\w+)=([\w\-,@]+.)/).to_h

  # Split each configuration option's values into an array
  config_options.transform_values! { |v| v.split(',') }

  # Define the path to the crypto policy file
  crypto_policy_file = '/etc/crypto-policies/back-ends/opensshserver.config'

  # Test that the crypto policy file is configured with the required algorithms
  describe "The crypto policy file #{crypto_policy_file}" do
    it 'is configured with the required algorithms' do
      expect(crypto_policy).not_to be_nil, "The crypto policy file #{crypto_policy_file} \ndoes not contain the required algorithms\n\n\t#{required_algorithms}."
    end
  end

  # Test that the MACS option in the crypto policy file contains the required algorithms in the correct order
  describe 'The MACs option in the crypto policy file' do
    it 'contains the required algorithms in the correct order' do
      expect(config_options['MACS']).to eq(required_algorithms), "The MACS option in the crypto policy file does not contain the required algorithms in the *exact order*:\n\n\texpected: #{required_algorithms}\n\tgot:#{config_options['MACS']}"
    end
  end
end
