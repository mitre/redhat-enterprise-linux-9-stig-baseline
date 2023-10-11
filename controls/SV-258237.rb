control 'SV-258237' do
  title 'RHEL 9 must use mechanisms meeting the requirements of applicable federal laws, executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Overriding the system crypto policy makes the behavior of Kerberos violate expectations, and makes system configuration more fragmented.'
  desc 'check', 'Verify that the symlink exists and targets the correct Kerberos crypto policy, with the following command:

file /etc/crypto-policies/back-ends/krb5.config

If command output shows the following line, Kerberos is configured to use the system-wide crypto policy:

/etc/crypto-policies/back-ends/krb5.config: symbolic link to /usr/share/crypto-policies/FIPS/krb5.txt

If the symlink does not exist or points to a different target, this is a finding.'
  desc 'fix', 'Configure Kerberos to use system crypto policy.

Create a symlink pointing to system crypto policy in the Kerberos configuration using the following command:

$ sudo ln -s /etc/crypto-policies/back-ends/krb5.config /usr/share/crypto-policies/FIPS/krb5.txt'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61978r926696_chk'
  tag severity: 'medium'
  tag gid: 'V-258237'
  tag rid: 'SV-258237r926698_rule'
  tag stig_id: 'RHEL-09-672025'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-61902r926697_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
