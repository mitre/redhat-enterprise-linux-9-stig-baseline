control 'SV-258149' do
  title 'The RHEL 8 audit records must be off-loaded onto a different system or
storage media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system
utility providing support for message logging.  Support for both internet and
UNIX domain sockets enables this utility to support both local and remote
logging.  Couple this utility with "gnutls" (which is a secure communications
library implementing the SSL, TLS and DTLS protocols), and you have a method to
securely encrypt and off-load auditing.

    Rsyslog provides three ways to forward message: the traditional UDP
transport, which is extremely lossy but standard; the plain TCP based
transport, which loses messages only during certain situations but is widely
available; and the RELP transport, which does not lose messages but is
currently available only as part of the rsyslogd 3.15.0 and above.
    Examples of each configuration:
    UDP *.* @remotesystemname
    TCP *.* @@remotesystemname
    RELP *.* :omrelp:remotesystemname:2514
    Note that a port number was given as there is no standard port for RELP.'
  desc 'check', 'Verify the audit system offloads audit records onto a different system or media from the system being audited with the following command:

     $ sudo grep @@ /etc/rsyslog.conf /etc/rsyslog.d/*.conf

     /etc/rsyslog.conf:*.* @@[logaggregationserver.example.mil]:[port]

If a remote server is not configured, or the line is commented out, ask the system administrator to indicate how the audit logs are offloaded to a different system or media.

If there is no evidence that the audit logs are being offloaded to another system or media, this is a finding.'
  desc 'fix', 'Configure the operating system to offload audit records onto a different system or media from the system being audited by specifying the remote logging server in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf" with the name or IP address of the log aggregation server.

For UDP:
     *.* @[logaggregationserver.example.mil]:[port]

For TCP:
     *.* @@[logaggregationserver.example.mil]:[port]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-230479'
  tag rid: 'SV-258149r917883_rule'
  tag stig_id: 'RHEL-08-030690'
  tag fix_id: 'F-33123r917882_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternative_logging_method') != ''
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  else
    describe command("grep @@ #{input('logging_conf_files').join(' ')}") do
      its('stdout') { should match(/^[^#]*:\*\.\*\s*@@[a-z.0-9]*:?[0-9]*?/) }
    end
  end
end
