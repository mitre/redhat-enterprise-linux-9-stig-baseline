control 'SV-258132' do
  title 'RHEL 9 must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Verify the certificate of the user or group is mapped to the corresponding user or group in the "sssd.conf" file with the following command:

$ sudo cat /etc/sssd/sssd.conf 
 
[certmap/testing.test/rule_name]
matchrule =<SAN>.*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

If the certmap section does not exist, ask the system administrator (SA) to indicate how certificates are mapped to accounts. If there is no evidence of certificate mapping, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to map the authenticated identity to the user or group account by adding or modifying the certmap section of the "/etc/sssd/sssd.conf" file based on the following example:

[certmap/testing.test/rule_name]
matchrule = .*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
dmains = testing.test

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

$ sudo systemctl restart sssd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61873r926381_chk'
  tag severity: 'medium'
  tag gid: 'V-258132'
  tag rid: 'SV-258132r926383_rule'
  tag stig_id: 'RHEL-09-631015'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag fix_id: 'F-61797r926382_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
