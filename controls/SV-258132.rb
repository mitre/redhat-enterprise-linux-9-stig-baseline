control 'SV-258132' do
  title 'RHEL 9 must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify the certificate of the user or group is mapped to the corresponding user or group in the "sssd.conf" file with the following command:

$ sudo find /etc/sssd/sssd.conf /etc/sssd/conf.d/ -type f -exec cat {} \\;
 
[certmap/testing.test/rule_name]
matchrule =<SAN>.*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

If the certmap section does not exist, ask the system administrator (SA) to indicate how certificates are mapped to accounts. 

If there is no evidence of certificate mapping, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to map the authenticated identity to the user or group account by adding or modifying the certmap section of the "/etc/sssd/sssd.conf" file based on the following example:

[certmap/testing.test/rule_name]
matchrule = .*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

$ sudo systemctl restart sssd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag gid: 'V-258132'
  tag rid: 'SV-258132r1045260_rule'
  tag stig_id: 'RHEL-09-631015'
  tag fix_id: 'F-61797r1014904_fix'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (c)', 'IA-5 (2) (a) (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe file('/etc/sssd/sssd.conf') do
    it { should exist }
    its('content') { should match(/^\s*\[certmap.*\]\s*$/) }
  end
end
