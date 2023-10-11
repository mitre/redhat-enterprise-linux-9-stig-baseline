control 'SV-257831' do
  title 'RHEL 9 must not have the telnet-server package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities are often overlooked and therefore, may remain unsecure. They increase the risk to the platform by providing additional attack vectors.

The telnet service provides an unencrypted remote access service, which does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to login using this service, the privileged user password could be compromised.

Removing the "telnet-server" package decreases the risk of accidental (or intentional) activation of the telnet service.'
  desc 'check', 'Verify that the telnet-server package is not installed with the following command:

$ sudo dnf list --installed telnet-server

Error: No matching Packages to list

If the "telnet-server" package is installed, this is a finding.'
  desc 'fix', 'Remove the telnet-server package with the following command:

$ sudo dnf remove telnet-server'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61572r925478_chk'
  tag severity: 'medium'
  tag gid: 'V-257831'
  tag rid: 'SV-257831r925480_rule'
  tag stig_id: 'RHEL-09-215040'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-61496r925479_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
