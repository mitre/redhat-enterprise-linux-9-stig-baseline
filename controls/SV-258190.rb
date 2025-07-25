control 'SV-258190' do
  title 'RHEL 9 must audit all uses of the init_module and finit_module system calls.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user logs on, the auid is set to the uid of the account being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each system call made by all programs on the system. Therefore, it is very important to use system call rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining system calls into one rule whenever possible.'
  desc 'check', 'Verify that RHEL 9 is configured to audit the execution of the "init_module" and "finit_module" system calls with the following command:

$ sudo auditctl -l | grep init_module

-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng

If both the "b32" and "b64" audit rules are not defined for the "init_module" system call, or any of the lines returned are commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to generate an audit event for any successful/unsuccessful use of the "init_module" and "finit_module" system calls by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng

To load the rules to the kernel immediately, use the following command:

$ sudo augenrules --load'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000477-GPOS-00222']
  tag gid: 'V-258190'
  tag rid: 'SV-258190r1045355_rule'
  tag stig_id: 'RHEL-09-654080'
  tag fix_id: 'F-61855r1045354_fix'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000135', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-3 (1)', 'AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  audit_syscalls = ['init_module', 'finit_module']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe 'Syscall' do
    audit_syscalls.each do |audit_syscall|
      it "#{audit_syscall} is audited properly" do
        audit_rule = auditd.syscall(audit_syscall)
        expect(audit_rule).to exist
        expect(audit_rule.action.uniq).to cmp 'always'
        expect(audit_rule.list.uniq).to cmp 'exit'
        if os.arch.match(/64/)
          expect(audit_rule.arch.uniq).to include('b32', 'b64')
        else
          expect(audit_rule.arch.uniq).to cmp 'b32'
        end
        expect(audit_rule.fields.flatten).to include('auid>=1000', 'auid!=-1')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_syscall])
      end
    end
  end
end
