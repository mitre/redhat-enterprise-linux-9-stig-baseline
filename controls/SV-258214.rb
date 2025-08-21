control 'SV-258214' do
  title 'Successful/unsuccessful uses of the shutdown command in RHEL 9 must generate an audit record.'
  desc 'Misuse of the shutdown command may cause availability issues for the system.'
  desc 'check', 'Verify that RHEL 9 is configured to audit the execution of the "shutdown" command with the following command:

$ sudo cat /etc/audit/rules.d/* | grep shutdown

-a always,exit -S all -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-shutdown

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "shutdown" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown

To load the rules to the kernel immediately, use the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-61955r1045425_chk'
  tag severity: 'medium'
  tag gid: 'V-258214'
  tag rid: 'SV-258214r1045427_rule'
  tag stig_id: 'RHEL-09-654200'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-61879r1045426_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  audit_command = '/usr/sbin/shutdown'

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
      auditctl_output = command("sudo auditctl -l | grep #{audit_command}").stdout.strip
      expect(auditctl_output).to match(/-S\s+all\b/)
    end
  end
end
