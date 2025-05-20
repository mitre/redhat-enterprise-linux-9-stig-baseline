control 'SV-272488' do
  title 'RHEL 9 must have the Postfix package installed.'
  desc 'Postfix is a free, open-source mail transfer agent (MTA) that sends and receives emails. It is a server-side application that can be used to set up a local mail server, create a null-client mail relay, use a Postfix server as a destination for multiple domains, or choose an LDAP directory instead of files for lookups. Postfix supports protocols such as LDAP, SMTP AUTH (SASL), and TLS. It uses the Simple Mail Transfer Protocol (SMTP) to transfer emails between servers.

'
  desc 'check', 'Verify that RHEL 9 has the Postfix package installed with the following command:

$ sudo dnf list --installed postfix

Example output:

postfix.x86_64                             2:3.5.25-1.el9 

If the "postfix" package is not installed, this is a finding.'
  desc 'fix', 'Install the Postfix package with the following command:
 
$ sudo dnf install postfix'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-76542r1082176_chk'
  tag severity: 'medium'
  tag gid: 'V-272488'
  tag rid: 'SV-272488r1082178_rule'
  tag stig_id: 'RHEL-09-215101'
  tag gtitle: 'SRG-OS-000304-GPOS-00121'
  tag fix_id: 'F-76447r1082177_fix'
  tag satisfies: ['SRG-OS-000304-GPOS-00121', 'SRG-OS-000343-GPOS-00134', 'SRG-OS-000363-GPOS-00150', 'SRG-OS-000447-GPOS-00201']
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']

  describe package('postfix') do
    it { should be_installed }
  end
end
