control 'SV-258147' do
  title 'RHEL 9 must encrypt the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

RHEL 9 installation media provides "rsyslogd", a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (a secure communications library implementing the SSL, TLS and DTLS protocols) creates a method to securely encrypt and offload auditing.

"Rsyslog" supported authentication modes include:
anon - anonymous authentication
x509/fingerprint - certificate fingerprint authentication
x509/certvalid - certificate validation only
x509/name - certificate validation and subject name authentication'
  desc 'check', %q(Verify RHEL 9 encrypts audit records offloaded onto a different system or media from the system being audited via rsyslog with the following command:

$ grep -i 'StreamDriver[\.]*Mode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

/etc/rsyslog.conf:$ActionSendStreamDriverMode 1 

If the value of the "$ActionSendStreamDriverMode or StreamDriver.Mode" option is not set to "1" or the line is commented out, this is a finding.

If the variable name "StreamDriverAuthMode" is present in an omfwd statement block, this is not a finding. However, if the "StreamDriverAuthMode" variable is in a module block, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to encrypt offloaded audit records via rsyslog by setting the following options in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf":

$ActionSendStreamDriverMode 1'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-258147'
  tag rid: 'SV-258147r1045290_rule'
  tag stig_id: 'RHEL-09-652045'
  tag fix_id: 'F-61812r926427_fix'
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
        command("grep -i '^\$DefaultNetstreamDriver' #{input('logging_conf_files').join(' ')} | awk -F ':' '{ print $2 }'").stdout
      }
      it { should match(/\$DefaultNetstreamDriver\s+gtls/) }
    end

    describe 'rsyslog configuration' do
      subject {
        command("grep -i '^\$ActionSendStreamDriverMode' #{input('logging_conf_files').join(' ')} | awk -F ':' '{ print $2 }'").stdout
      }
      it { should match(/\$ActionSendStreamDriverMode\s+1/) }
    end
  end
end
