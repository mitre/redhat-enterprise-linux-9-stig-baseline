control 'SV-258242' do
  title 'RHEL 9 must implement DOD-approved encryption in the bind package.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 9 incorporates system-wide crypto policies by default. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/ directory.

'
  desc 'check', %q(Verify that BIND uses the system crypto policy with the following command:

Note: If the "bind" package is not installed, this requirement is Not Applicable.

$ sudo grep include /etc/named.conf 

include "/etc/crypto-policies/back-ends/bind.config";' 

If BIND is installed and the BIND config file doesn't contain the  include "/etc/crypto-policies/back-ends/bind.config" directive, or the line is commented out, this is a finding.)
  desc 'fix', 'Configure BIND to use the system crypto policy.

Add the following line to the "options" section in "/etc/named.conf":

include "/etc/crypto-policies/back-ends/bind.config";'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61983r926711_chk'
  tag severity: 'medium'
  tag gid: 'V-258242'
  tag rid: 'SV-258242r926713_rule'
  tag stig_id: 'RHEL-09-672050'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-61907r926712_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)']
end
