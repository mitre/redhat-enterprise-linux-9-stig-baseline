control 'SV-258148' do
  title 'RHEL 9 must encrypt via the gtls driver the transfer of audit records offloaded onto a different system or media from the system being audited via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

RHEL 9 installation media provides "rsyslogd", a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (a secure communications library implementing the SSL, TLS and DTLS protocols) creates a method to securely encrypt and offload auditing.

'
  desc 'check', %q(Verify RHEL 9 uses the gtls driver to encrypt audit records offloaded onto a different system or media from the system being audited with the following command:

$ grep -Ei 'DefaultNetStreamDriver\b|StreamDriver.Name' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

/etc/rsyslog.conf:$DefaultNetstreamDriver gtls

If the value of the "$DefaultNetstreamDriver or StreamDriver" option is not set to "gtls" or the line is commented out, this is a finding.

If the variable name "StreamDriver" is present in an omfwd statement block, this is not a finding. However, if the "StreamDriver" variable is in a module block, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to use the gtls driver to encrypt offloaded audit records by setting the following options in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf":

$DefaultNetstreamDriver gtls'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61889r1045291_chk'
  tag severity: 'medium'
  tag gid: 'V-258148'
  tag rid: 'SV-258148r1045292_rule'
  tag stig_id: 'RHEL-09-652050'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-61813r926430_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'
  tag 'container'

  setting = 'DefaultNetstreamDriver'
  expected_value = 'gtls'

  pattern = /[^#]\$#{setting}\s*(?<value>\w+)$/
  setting_check = command("grep -i #{setting} /etc/rsyslog.conf /etc/rsyslog.d/*.conf").stdout.strip.scan(pattern).flatten

  describe 'Rsyslogd DefaultNetstreamDriver' do
    if setting_check.empty?
      it 'should be set' do
        expect(setting_check).to_not be_empty, "'#{setting}' not found (or commented out) in conf file(s)"
      end
    else
      it 'should only be set once' do
        expect(setting_check.length).to eq(1), "'#{setting}' set more than once in conf file(s)"
      end
      it "should be set to '#{expected_value}'" do
        expect(setting_check.first).to eq(expected_value), "'#{setting}' set to '#{setting_check.first}' in conf file(s)"
      end
    end
  end

  # netstream_driver = command('grep -i $DefaultNetstreamDriver /etc/rsyslog.conf /etc/rsyslog.d/*').stdout.strip

  # describe "Rsyslog config" do
  #   it "should encrypt audit records for transfer" do
  #     expect(modload).to be_empty, "ModLoad settings found:\n\t- #{modload.join("\n\t- ")}"
  #   end
  # end
end
