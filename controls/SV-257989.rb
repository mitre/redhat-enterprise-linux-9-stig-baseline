control 'SV-257989' do
  title 'RHEL 9 must implement DOD-approved encryption ciphers to protect the confidentiality of SSH server connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 9 incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.'
  desc 'check', 'Verify the SSH client is configured to use only ciphers employing FIPS 140-3 approved algorithms with the following command:

$ sudo grep -i ciphers /etc/crypto-policies/back-ends/openssh.config 

Ciphers aes-256-gcm@openssh.com, chacha20-poly1305@openssh.com, aes256-ctr,aes128-gcm@openssh.com,aes128-ctr

If the cipher entries in the "openssh.config" file have any ciphers other than "aes-256-gcm@openssh.com, chacha20-poly1305@openssh.com, aes256-ctr,aes128-gcm@openssh.com,aes128-ctr", the order differs from the example above, they are missing, or commented out, this is a finding.'
  desc 'fix', 'Configure the RHEL 9 SSH client to use only ciphers employing FIPS 140-3 approved algorithms by updating the "/etc/crypto-policies/back-ends/openssh.config" file with the following line:

Ciphers aes-256-gcm@openssh.com, chacha20-poly1305@openssh.com, aes256-ctr,aes128-gcm@openssh.com,aes128-ctr

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61730r925952_chk'
  tag severity: 'medium'
  tag gid: 'V-257989'
  tag rid: 'SV-257989r925954_rule'
  tag stig_id: 'RHEL-09-255065'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-61654r925953_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
