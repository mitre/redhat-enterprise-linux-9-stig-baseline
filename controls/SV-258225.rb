control 'SV-258225' do
  title 'Successful/unsuccessful modifications to the lastlog file in RHEL 8
must generate an audit record.'
  desc 'Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    The list of audited events is the set of events for which audits are to be
generated. This set of events is typically a subset of the list of all events
for which the system is capable of generating audit records.

    DoD has defined the list of events for which RHEL 8 will provide an audit
record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
privileged activities or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.'
  desc 'check', 'Verify RHEL 8 generates an audit record when successful/unsuccessful
modifications to the "lastlog" file by performing the following command to
check the file system rules in "/etc/audit/audit.rules":

    $ sudo grep -w lastlog /etc/audit/audit.rules

    -w /var/log/lastlog -p wa -k logins

    If the command does not return a line, or the line is commented out, this
is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any
successful/unsuccessful modifications to the "lastlog" file by adding or
updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

    -w /var/log/lastlog -p wa -k logins

    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000473-GPOS-00218']
  tag gid: 'V-230467'
  tag rid: 'SV-258225r627750_rule'
  tag stig_id: 'RHEL-08-030600'
  tag fix_id: 'F-33111r568148_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
  tag 'host'

  audit_command = '/var/log/lastlog'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.permissions.flatten).to include('w', 'a')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
    end
  end
end
