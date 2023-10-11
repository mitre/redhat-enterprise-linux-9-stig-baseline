control 'SV-257983' do
  title 'RHEL 9 SSHD must accept public key authentication.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. A privileged account is defined as an information system account with authorizations of a privileged user. A DOD CAC with DOD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'Verify that RHEL 9 SSH daemon accepts public key encryption with the following command:
 
$ sudo grep -i PubkeyAuthentication /etc/ssh/sshd_config

PubkeyAuthentication yes
 
If "PubkeyAuthentication" is set to no, the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'To configure the system add or modify the following line in "/etc/ssh/sshd_config".

PubkeyAuthentication yes

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61724r925934_chk'
  tag severity: 'medium'
  tag gid: 'V-257983'
  tag rid: 'SV-257983r925936_rule'
  tag stig_id: 'RHEL-09-255035'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-61648r925935_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)']
end
