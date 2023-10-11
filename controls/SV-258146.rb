control 'SV-258146' do
  title 'RHEL 9 must authenticate the remote logging server for offloading audit logs via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

RHEL 9 installation media provides "rsyslogd", a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (a secure communications library implementing the SSL, TLS and DTLS protocols) creates a method to securely encrypt and offload auditing.

"Rsyslog" supported authentication modes include:
anon - anonymous authentication
x509/fingerprint - certificate fingerprint authentication
x509/certvalid - certificate validation only
x509/name - certificate validation and subject name authentication

'
  desc 'check', %q(Verify RHEL 9 authenticates the remote logging server for offloading audit logs with the following command:

$ sudo grep -i '$ActionSendStreamDriverAuthMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 

 /etc/rsyslog.conf:$ActionSendStreamDriverAuthMode x509/name 

If the value of the "$ActionSendStreamDriverAuthMode" option is not set to "x509/name" or the line is commented out, ask the system administrator (SA) to indicate how the audit logs are offloaded to a different system or media. 

If there is no evidence that the transfer of the audit logs being offloaded to another system or media is encrypted, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to authenticate the remote logging server for offloading audit logs by setting the following option in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf":

$ActionSendStreamDriverAuthMode x509/name'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61887r926423_chk'
  tag severity: 'medium'
  tag gid: 'V-258146'
  tag rid: 'SV-258146r926425_rule'
  tag stig_id: 'RHEL-09-652040'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-61811r926424_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
