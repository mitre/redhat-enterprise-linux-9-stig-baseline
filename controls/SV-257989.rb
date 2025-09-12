control 'SV-257989' do
  title 'The RHEL 9 SSH server must be configured to use only DOD-approved encryption ciphers employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 9 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.'
  desc 'check', 'Verify the SSH server is configured to use only ciphers employing FIPS 140-3 approved algorithms.

To verify the ciphers in the systemwide SSH configuration file, use the following command:

$ sudo grep -i Ciphers /etc/crypto-policies/back-ends/opensshserver.config
Ciphers aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr

If the cipher entries in the "opensshserver.config" file have any ciphers other than "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr", or they are missing or commented out, this is a finding.'
  desc 'fix', 'Configure the RHEL 9 SSH server to use only ciphers employing FIPS 140-3 approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag gid: 'V-257989'
  tag rid: 'SV-257989r1051240_rule'
  tag stig_id: 'RHEL-09-255065'
  tag fix_id: 'F-61654r1051239_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable - SSH is not installed within containerized RHEL', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?)
  }

  approved_ciphers = input('approved_openssh_server_conf')['ciphers']

  options = { assignment_regex: /^(\S+)\s+(\S+)$/ }
  opensshserver_conf = parse_config_file('/etc/crypto-policies/back-ends/openssh.config', options).params.to_h { |k, v| [k.downcase, v.split(',')] }

  actual_ciphers = opensshserver_conf['ciphers'].join(',')

  describe 'OpenSSH server configuration' do
    it 'implement approved encryption ciphers' do
      expect(actual_ciphers).to eq(approved_ciphers), "OpenSSH server cipher configuration actual value:\n\t#{actual_ciphers}\ndoes not match the expected value:\n\t#{approved_ciphers}"
    end
  end
end
