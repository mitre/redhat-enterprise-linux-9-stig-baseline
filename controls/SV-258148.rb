control 'SV-258148' do
  title 'RHEL 9 must encrypt via the gtls driver the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

RHEL 9 installation media provides "rsyslogd", a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (a secure communications library implementing the SSL, TLS and DTLS protocols) creates a method to securely encrypt and offload auditing.

'
  desc 'check', %q(Verify RHEL 9 uses the gtls driver to encrypt audit records offloaded onto a different system or media from the system being audited with the following command:

$ sudo grep -i '$DefaultNetstreamDriver' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 

/etc/rsyslog.conf:$DefaultNetstreamDriver gtls 

If the value of the "$DefaultNetstreamDriver" option is not set to "gtls" or the line is commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to use the gtls driver to encrypt offloaded audit records by setting the following options in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf":

$DefaultNetstreamDriver gtls'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61889r926429_chk'
  tag severity: 'medium'
  tag gid: 'V-258148'
  tag rid: 'SV-258148r926431_rule'
  tag stig_id: 'RHEL-09-652050'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-61813r926430_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
