control 'SV-270178' do
  title 'The RHEL 9 SSH client must be configured to use only DOD-approved Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection. 

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography, enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash. 

RHEL 9 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssh.config file.'
  desc 'check', 'Verify the SSH client is configured to use only MACs employing FIPS 140-3 approved algorithms.

To verify the MACs in the systemwide SSH configuration file, use the following command:

$ grep -i MACs /etc/crypto-policies/back-ends/openssh.config

MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

If the MACs entries in the "openssh.config" file have any hashes other than "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512", or they are missing or commented out, this is a finding.'
  desc 'fix', 'Configure the SSH client to use only MACs employing FIPS 140-3 approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-74211r1051241_chk'
  tag severity: 'medium'
  tag gid: 'V-270178'
  tag rid: 'SV-270178r1051243_rule'
  tag stig_id: 'RHEL-09-255070'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-74112r1051242_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  only_if('Control not applicable - SSH is not installed within containerized RHEL', impact: 0.0) {
    !virtualization.system.eql?('docker') || file('/etc/ssh/sshd_config').exist?
  }

  describe file('/etc/crypto-policies/back-ends/openssh.config') do
    it { should exist }
    its('content') { should match /^MACs\s+hmac-sha2-256-etm@openssh\.com,hmac-sha2-512-etm@openssh\.com,hmac-sha2-256,hmac-sha2-512$/ }
  end
end
