control 'SV-258232' do
  title 'RHEL 9 IP tunnels must use FIPS 140-2/140-3 approved cryptographic algorithms.'
  desc 'Overriding the system crypto policy makes the behavior of the Libreswan service violate expectations, and makes system configuration more fragmented.'
  desc 'check', 'Verify that the IPsec service uses the system crypto policy with the following command:

Note: If the ipsec service is not installed, this requirement is Not Applicable.

$ sudo grep include /etc/ipsec.conf /etc/ipsec.d/*.conf

/etc/ipsec.conf:include /etc/crypto-policies/back-ends/libreswan.config

If the ipsec configuration file does not contain "include /etc/crypto-policies/back-ends/libreswan.config", this is a finding.'
  desc 'fix', 'Configure Libreswan to use the system cryptographic policy.

Add the following line to "/etc/ipsec.conf":

include /etc/crypto-policies/back-ends/libreswan.config'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61973r926681_chk'
  tag severity: 'medium'
  tag gid: 'V-258232'
  tag rid: 'SV-258232r958408_rule'
  tag stig_id: 'RHEL-09-671020'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-61897r926682_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  expected_value = input('approved_crypto_backend')

  setting_check = command('grep include /etc/ipsec.conf /etc/ipsec.d/*.conf').stdout.strip.match?(/^.*:?[^#]include\s*#{expected_value}$/)

  describe 'RHEL9 IPsec config' do
    it "should include the conf file '#{expected_value}'" do
      expect(setting_check).to eq(true), "Conf file '#{expected_value}' not included in ipsec config"
    end
  end
end
