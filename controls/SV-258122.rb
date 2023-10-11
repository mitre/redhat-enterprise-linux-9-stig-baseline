control 'SV-258122' do
  title 'RHEL 9 must enable certificate based smart card authentication.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. A privileged account is defined as an information system account with authorizations of a privileged user. The DOD Common Access Card (CAC) with DOD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'Verify that RHEL 9 has smart cards are enabled in System Security Services Daemon (SSSD), run the following command:

$ sudo grep pam_cert_auth /etc/sssd/sssd.conf

pam_cert_auth = True 

If "pam_cert_auth" is not set to "True", the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Edit the file "/etc/sssd/sssd.conf" and add or edit the following line:

pam_cert_auth = True'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61863r926351_chk'
  tag severity: 'medium'
  tag gid: 'V-258122'
  tag rid: 'SV-258122r926353_rule'
  tag stig_id: 'RHEL-09-611165'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-61787r926352_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000105-GPOS-00052']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-001948']
  tag nist: ['IA-2 (1)', 'IA-2 (11)']
end
