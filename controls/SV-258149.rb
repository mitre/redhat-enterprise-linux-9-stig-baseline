control 'SV-258149' do
  title 'RHEL 9 must be configured to forward audit records via TCP to a different system or media from the system being audited via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

RHEL 9 installation media provides "rsyslogd", a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (a secure communications library implementing the SSL, TLS and DTLS protocols) creates a method to securely encrypt and offload auditing.

Rsyslog provides three ways to forward message: the traditional UDP transport, which is extremely lossy but standard; the plain TCP based transport, which loses messages only during certain situations but is widely available; and the RELP transport, which does not lose messages but is currently available only as part of the rsyslogd 3.15.0 and above.

Examples of each configuration:
UDP *.* @remotesystemname
TCP *.* @@remotesystemname
RELP *.* :omrelp:remotesystemname:2514
Note that a port number was given as there is no standard port for RELP.

'
  desc 'check', 'Verify that RHEL 9 audit system offloads audit records onto a different system or media from the system being audited via rsyslog using TCP with the following command:

$ sudo grep @@ /etc/rsyslog.conf /etc/rsyslog.d/*.conf

/etc/rsyslog.conf:*.* @@[remoteloggingserver]:[port]

If a remote server is not configured, or the line is commented out, ask the system administrator (SA) to indicate how the audit logs are offloaded to a different system or media. 

If there is no evidence that the audit logs are being offloaded to another system or media, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to offload audit records onto a different system or media from the system being audited via TCP using rsyslog by specifying the remote logging server in "/etc/rsyslog.conf"" or "/etc/rsyslog.d/[customfile].conf" with the name or IP address of the log aggregation server.

*.* @@[remoteloggingserver]:[port]"'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61890r926432_chk'
  tag severity: 'medium'
  tag gid: 'V-258149'
  tag rid: 'SV-258149r926434_rule'
  tag stig_id: 'RHEL-09-652055'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-61814r926433_fix'
  tag satisfies: ['SRG-OS-000479-GPOS-00224', 'SRG-OS-000480-GPOS-00227', 'SRG-OS-000342-GPOS-00133']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001851']
  tag nist: ['CM-6 b', 'AU-4 (1)']
end
