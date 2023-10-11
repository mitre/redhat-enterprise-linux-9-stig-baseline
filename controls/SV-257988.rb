control 'SV-257988' do
  title 'RHEL 9 must implement DOD-approved encryption ciphers to protect the confidentiality of SSH client connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 9 incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.'
  desc 'check', 'Verify that system-wide crypto policies are in effect with the following command:

$ sudo grep Include /etc/ssh/sshd_config  /etc/ssh/sshd_config.d/*

/etc/ssh/sshd_config:Include /etc/ssh/sshd_config.d/*.conf
/etc/ssh/sshd_config.d/50-redhat.conf:Include /etc/crypto-policies/back-ends/opensshserver.config

If "Include /etc/ssh/sshd_config.d/*.conf" or "Include /etc/crypto-policies/back-ends/opensshserver.config" are not included in the system sshd config or the file "/etc/ssh/sshd_config.d/50-redhat.conf" is missing, this is a finding.'
  desc 'fix', 'Configure the RHEL 9 SSH daemon to use system-wide crypto policies by running the following commands:

$ sudo dnf reinstall openssh-clients'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61729r925949_chk'
  tag severity: 'medium'
  tag gid: 'V-257988'
  tag rid: 'SV-257988r925951_rule'
  tag stig_id: 'RHEL-09-255060'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-61653r925950_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
