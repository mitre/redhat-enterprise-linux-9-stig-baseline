control 'SV-258195' do
  title 'Successful/unsuccessful uses of the kmod command in RHEL 8 must
generate an audit record.'
  desc 'Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter). The "kmod" command is
used to control Linux Kernel modules.

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
  desc 'check', 'Verify if RHEL 8 is configured to audit the execution of the module
management program "kmod", by running the following command:

    $ sudo grep "/usr/bin/kmod" /etc/audit/audit.rules

    -a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset
-k modules

    If the command does not return a line, or the line is commented out, this
is a finding.'
  desc 'fix', 'Configure RHEL 8 to audit the execution of the module management program
"kmod" by adding or updating the following line to
"/etc/audit/rules.d/audit.rules":

    -a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset
-k modules

    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag gid: 'V-230465'
  tag rid: 'SV-258195r627750_rule'
  tag stig_id: 'RHEL-08-030580'
  tag fix_id: 'F-33109r568142_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
  tag 'host'

  audit_command = '/usr/bin/kmod'

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
