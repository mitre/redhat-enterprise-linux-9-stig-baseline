control 'V-257991' do
  title 'RHEL 9 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 9 incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.'
  desc 'check', 'Verify SSH server is configured to use only ciphers employing FIPS 140-3 approved algorithms with the following command:

$ sudo grep -i macs /etc/crypto-policies/back-ends/openssh.config
MACs hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512

If the MACs entries in the "openssh.config" file have any hashes other than "hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,hmac-sha2-512", the order differs from the example above, or they are missing or commented out, this is a finding.'
  desc 'fix', 'Configure the RHEL 9 SSH server to use only MACs employing FIPS 140-3 approved algorithms by updating the "/etc/crypto-policies/back-ends/openssh.config" file with the following line:

MACs hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61732r952186_chk'
  tag severity: 'medium'
  tag gid: 'V-257991'
  tag rid: 'SV-257991r991554_rule'
  tag stig_id: 'RHEL-09-255075'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-61656r952187_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
