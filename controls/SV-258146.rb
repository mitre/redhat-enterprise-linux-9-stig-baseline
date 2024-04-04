control 'SV-258146' do
  title 'RHEL 8 must authenticate the remote logging server for off-loading
audit logs.'
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

    "Rsyslog" supported authentication modes include:
    anon - anonymous authentication
    x509/fingerprint - certificate fingerprint authentication
    x509/certvalid - certificate validation only
    x509/name - certificate validation and subject name authentication.'
  desc 'check', %q(Verify the operating system authenticates the remote logging server for
off-loading audit logs with the following command:

    $ sudo grep -i '$ActionSendStreamDriverAuthMode' /etc/rsyslog.conf
/etc/rsyslog.d/*.conf

    /etc/rsyslog.conf:$ActionSendStreamDriverAuthMode x509/name

    If the value of the "$ActionSendStreamDriverAuthMode" option is not set
to "x509/name" or the line is commented out, ask the System Administrator to
indicate how the audit logs are off-loaded to a different system or media.

    If there is no evidence that the transfer of the audit logs being
off-loaded to another system or media is encrypted, this is a finding.)
  desc 'fix', 'Configure the operating system to authenticate the remote logging server
for off-loading audit logs by setting the following option in
"/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf":

    $ActionSendStreamDriverAuthMode x509/name'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-230482'
  tag rid: 'SV-258146r877390_rule'
  tag stig_id: 'RHEL-08-030720'
  tag fix_id: 'F-33126r568193_fix'
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
    describe 'rsyslog configuration' do
      subject {
        command("grep -i '^\$ActionSendStreamDriverAuthMode' #{input('logging_conf_files').join(' ')}  | awk -F ':' '{ print $2 }'").stdout
      }
      it { should match %r{\$ActionSendStreamDriverAuthMode\s+x509/name} }
    end
  end
end
