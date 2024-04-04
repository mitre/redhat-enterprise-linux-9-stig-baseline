control 'SV-258162' do
  title 'RHEL 8 must take appropriate action when the internal event queue is
full.'
  desc 'Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system
utility providing support for message logging.  Support for both internet and
UNIX domain sockets enables this utility to support both local and remote
logging.  Couple this utility with "gnutls" (which is a secure communications
library implementing the SSL, TLS and DTLS protocols), and you have a method to
securely encrypt and off-load auditing.'
  desc 'check', 'Verify the audit system is configured to take an appropriate action when
the internal event queue is full:

    $ sudo grep -i overflow_action /etc/audit/auditd.conf

    overflow_action = syslog

    If the value of the "overflow_action" option is not set to "syslog",
"single", "halt", or the line is commented out, ask the System
Administrator to indicate how the audit logs are off-loaded to a different
system or media.

    If there is no evidence that the transfer of the audit logs being
off-loaded to another system or media takes appropriate action if the internal
event queue becomes full, this is a finding.'
  desc 'fix', 'Edit the /etc/audit/auditd.conf file and add or update the
"overflow_action" option:

    overflow_action = syslog

    The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-230480'
  tag rid: 'SV-258162r877390_rule'
  tag stig_id: 'RHEL-08-030700'
  tag fix_id: 'F-33124r568187_fix'
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
    describe parse_config_file('/etc/audit/auditd.conf') do
      its('overflow_action') { should match(/syslog$|single$|halt$/i) }
    end
  end
end
