control 'SV-258225' do
  title 'RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /var/log/lastlog.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', 'Verify RHEL 9 generates audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/lastlog" with the following command:

$ sudo auditctl -l | grep /var/log/lastlog

-w /var/log/lastlog -p wa -k logins

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/var/log/lastlog".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /var/log/lastlog -p wa -k logins

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000470-GPOS-00214']
  tag gid: 'V-258225'
  tag rid: 'SV-258225r926662_rule'
  tag stig_id: 'RHEL-09-654255'
  tag fix_id: 'F-61890r926661_fix'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000135', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-3 (1)', 'AU-12 c', 'MA-4 (1) (a)']
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
