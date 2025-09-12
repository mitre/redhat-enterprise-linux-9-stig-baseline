control 'SV-257983' do
  title 'RHEL 9 SSHD must accept public key authentication.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. A privileged account is defined as an information system account with authorizations of a privileged user. A DOD common access card (CAC) with DOD-approved PKI is an example of multifactor authentication.'
  desc 'check', %q(Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is Not Applicable.

Verify that RHEL 9 SSH daemon accepts public key encryption with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*pubkeyauthentication'

PubkeyAuthentication yes

If "PubkeyAuthentication" is set to no, the line is commented out, or the line is missing, this is a finding.)
  desc 'fix', 'To configure the system, add or modify the following line in "/etc/ssh/sshd_config" or in a file in "/etc/ssh/sshd_config.d".

PubkeyAuthentication yes

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-61724r1045022_chk'
  tag severity: 'medium'
  tag gid: 'V-257983'
  tag rid: 'SV-257983r1045024_rule'
  tag stig_id: 'RHEL-09-255035'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-61648r1045023_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('PubkeyAuthentication') { should cmp 'yes' }
  end
end
