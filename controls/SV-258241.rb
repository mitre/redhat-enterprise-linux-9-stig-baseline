control 'SV-258241' do
  title 'RHEL 9 must implement a FIPS 140-3 compliant systemwide cryptographic policy.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.'
  desc 'check', %q(Verify that RHEL 9 is set to use a FIPS 140-3 compliant systemwide cryptographic policy.

$ update-crypto-policies --show

FIPS

If the systemwide crypto policy is not set to "FIPS", this is a finding.

Inspect the contents of the REQUIRE.pmod file (if it exists) to ensure that only authorized modifications to the current policy are included with the following command:

$ cat /etc/crypto-policies/policies/modules/REQUIRE.pmod

Note: If subpolicies have been configured, they could be listed in a colon-separated list starting with FIPS as follows FIPS:<SUBPOLICY-NAME>:<SUBPOLICY-NAME>. This is not a finding.

If the AD-SUPPORT subpolicy module is included (e.g., "FIPS:AD-SUPPORT"), and Active Directory support is not documented as an operational requirement with the information system security officer (ISSO), this is a finding.

If the NO-ENFORCE-EMS subpolicy module is included (e.g., "FIPS:NO-ENFORCE-EMS"), and not enforcing EMS is not documented as an operational requirement with the ISSO, this is a finding.

Verify the current minimum crypto-policy configuration with the following commands:

$ grep -E 'rsa_size|hash' /etc/crypto-policies/state/CURRENT.pol
hash = SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512 SHAKE-256
min_rsa_size = 2048

If the "hash" values do not include at least the following FIPS 140-3 compliant algorithms  "SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512 SHAKE-256", this is a finding.

If there are algorithms that include "SHA1" or a hash value less than "256" this is a finding.

If the "min_rsa_size" is not set to a value of at least 2048, this is a finding.

If these commands do not return any output, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to use a FIPS 140-3 compliant systemwide cryptographic policy.

Create subpolicies for enhancements to the systemwide crypto-policy with the following commands:

Create or edit the SCOPES-AND-WILDCARDS policy module in a text editor and insert options that modify the systemwide cryptographic policy as follows:
$ sudo vi /etc/crypto-policies/policies/modules/SCOPES-AND-WILDCARDS.pmod

Add the following lines to the policy:
# Disable CHACHA20-POLY1305 for the TLS protocol (OpenSSL, GnuTLS, NSS, and OpenJDK)
cipher@TLS = -CHACHA20-POLY1305

# Disable all CBC mode ciphers for the SSH protocol (libssh and OpenSSH)
cipher@SSH = -*-CBC

Create or edit the OPENSSH-SUBPOLICY module in a text editor and insert options that modify the systemwide crypto-policy as follows:
$ sudo vi /etc/crypto-policies/policies/modules/OPENSSH-SUBPOLICY.pmod

Add the following lines to the policy:
# Define ciphers for OpenSSH
cipher@SSH=AES-256-GCM AES-128-GCM AES-256-CTR AES-128-CTR

# Define MACs for OpenSSH
mac@SSH=HMAC-SHA2-512 HMAC-SHA2-256

Create or edit the REQUIRE.pmod file and add the following lines to include the subpolicies in the FIPS configuration with the following command:

$ sudo vi /etc/crypto-policies/policies/modules/REQUIRE.pmod

Add the following lines to REQUIRE.pmod:
@OPENSSH-SUBPOLICY
@SCOPES-AND-WILDCARDS

Apply the policy enhancements to the FIPS systemwide cryptographic policy level with the following command:

$ sudo update-crypto-policies --set FIPS

Note: If additional subpolicies are being employed, they should be added to the REQUIRE.pmod as well. REQUIRE.pmod is included in the systemwide crypto-policy when it is set.

To make the cryptographic settings effective for already running services and applications, restart the system:
$ sudo reboot'
  impact 0.5
  tag check_id: 'C-61982r1051257_chk'
  tag severity: 'medium'
  tag gid: 'V-258241'
  tag rid: 'SV-258241r1051259_rule'
  tag stig_id: 'RHEL-09-215105'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-61906r1051258_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe command('update-crypto-policies --show') do
    its('stdout') { should match(/FIPS/) }
  end

  describe parse_config_file('/etc/crypto-policies/state/CURRENT.pol') do
    its(['min_rsa_size']) { should cmp >= 2048 }
    its(['hash']) {
      should include 'SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA2-224',
                     'SHA3-256', 'SHA3-384', 'SHA3-512', 'SHAKE-256'
    }
    its(['hash']) { should_not match(/SHA-?1\b/i) }
    its(['hash']) {
      is_expected.to satisfy('no hash size < 256 (except 224)') { |s|
                       sizes = s.scan(/-(\d+)/).flatten.map(&:to_i)
                       (sizes - [224]).all? { |n| n >= 256 }
                     }
    }
  end
end
