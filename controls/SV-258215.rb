control 'SV-258215' do
  title 'Successful/unsuccessful uses of the umount system call in RHEL 9 must generate an audit record.'
  desc 'The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.'
  desc 'check', %q(Verify that RHEL 9 generates an audit record for all uses of the "umount" and system call with the following command:

$ sudo auditctl -l | grep b32 | grep 'umount\b'

-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=-1 -F key=privileged-umount

If the command does not return a line, or the line is commented out, this is a finding.)
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "umount" system call by adding or updating the following rules in "/etc/audit/audit.rules" and adding the following rules to "/etc/audit/rules.d/perm_mod.rules" or updating the existing rules in files in the "/etc/audit/rules.d/" directory:

-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=unset -k privileged-umount

To load the rules to the kernel immediately, use the following command:

$ sudo augenrules --load'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag gid: 'V-258215'
  tag rid: 'SV-258215r1045430_rule'
  tag stig_id: 'RHEL-09-654205'
  tag fix_id: 'F-61880r1045429_fix'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_syscalls = ['umount']

  describe 'Syscall' do
    audit_syscalls.each do |audit_syscall|
      it "#{audit_syscall} is audited properly" do
        audit_rule = auditd.syscall(audit_syscall)
        expect(audit_rule).to exist
        expect(audit_rule.action.uniq).to cmp 'always'
        expect(audit_rule.list.uniq).to cmp 'exit'
        expect(audit_rule.arch.uniq).to cmp 'b32'
        expect(audit_rule.fields.flatten).to include('auid>=1000', 'auid!=-1')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_syscall])
      end
    end
  end
end
