control 'SV-258186' do
  title 'Successful/unsuccessful uses of setsebool in RHEL 8 must generate an
audit record.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible
if audit records do not contain enough information.

    At a minimum, the organization must audit the full-text recording of
privileged commands. The organization must maintain audit trails in sufficient
detail to reconstruct events to determine the cause and impact of compromise.
The "setsebool" command sets the current state of a particular SELinux
boolean or a list of booleans to a given value.

    When a user logs on, the AUID is set to the UID of the account that is
being authenticated. Daemons are not user sessions and have the loginuid set to
"-1". The AUID representation is an unsigned 32-bit integer, which equals
"4294967295". The audit system interprets "-1", "4294967295", and
"unset" in the same way.'
  desc 'check', 'Verify that an audit event is generated for any successful/unsuccessful use
of "setsebool" by performing the following command to check the file system
rules in "/etc/audit/audit.rules":

    $ sudo grep -w "setsebool" /etc/audit/audit.rules

    -a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F
auid!=unset -k privileged-unix-update

    If the command does not return a line, or the line is commented out, this
is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any
successful/unsuccessful uses of the "setsebool" by adding or updating the
following rule in the "/etc/audit/rules.d/audit.rules" file:

    -a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F
auid!=unset -k privileged-unix-update

    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag gid: 'V-230432'
  tag rid: 'SV-258186r627750_rule'
  tag stig_id: 'RHEL-08-030316'
  tag fix_id: 'F-33076r568043_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
  tag 'host'

  audit_command = '/usr/sbin/setsebool'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.action.uniq).to cmp 'always'
      expect(audit_rule.list.uniq).to cmp 'exit'
      expect(audit_rule.fields.flatten).to include('perm=x', 'auid>=1000', 'auid!=-1')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
