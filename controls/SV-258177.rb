control 'SV-258177' do
  title 'RHEL 9 must audit all uses of the chmod, fchmod, and fchmodat system calls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user logs on, the auid is set to the uid of the account being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each system call made by all programs on the system. Therefore, it is very important to use system call rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining system calls into one rule whenever possible.'
  desc 'check', 'Verify that RHEL 9 is configured to audit the execution of the "chmod", "fchmod", and "fchmodat" system calls with the following command:

$ sudo auditctl -l | grep chmod

-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod

If both the "b32" and "b64" audit rules are not defined for the "chmod", "fchmod", and "fchmodat" system calls, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to generate audit records upon successful/unsuccessful attempts to use the "chmod", "fchmod", and "fchmodat" syscalls.

Add or update the following rules in "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000458-GPOS-00203']
  tag gid: 'V-258177'
  tag rid: 'SV-258177r926518_rule'
  tag stig_id: 'RHEL-09-654015'
  tag fix_id: 'F-61842r926517_fix'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000135', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-3 (1)', 'AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  audit_syscalls = ['chmod', 'fchmod', 'fchmodat']

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
