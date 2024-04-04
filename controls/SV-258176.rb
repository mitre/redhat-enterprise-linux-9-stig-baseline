control 'SV-258176' do
  title 'The RHEL 8 audit system must be configured to audit the execution of
privileged functions and prevent all software from executing at higher
privilege levels than users executing the software.'
  desc 'Misuse of privileged functions, either intentionally or
unintentionally by authorized users, or by unauthorized external entities that
have compromised information system accounts, is a serious and ongoing concern
and can have significant adverse impacts on organizations. Auditing the use of
privileged functions is one way to detect such misuse and identify the risk
from insider threats and the advanced persistent threat.'
  desc 'check', 'Verify RHEL 8 audits the execution of privileged functions.

    Check if RHEL 8 is configured to audit the execution of the "execve"
system call, by running the following command:

    $ sudo grep execve /etc/audit/audit.rules

    -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv
    -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv

    -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv
    -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv

    If the command does not return all lines, or the lines are commented out,
this is a finding.'
  desc 'fix', 'Configure RHEL 8 to audit the execution of the "execve" system call.

    Add or update the following file system rules to
"/etc/audit/rules.d/audit.rules":

    -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv
    -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv

    -a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv
    -a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv

    The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag satisfies: ['SRG-OS-000326-GPOS-00126', 'SRG-OS-000327-GPOS-00127']
  tag gid: 'V-230386'
  tag rid: 'SV-258176r854037_rule'
  tag stig_id: 'RHEL-08-030000'
  tag fix_id: 'F-33030r567905_fix'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_syscalls = ['execve']

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
        expect(audit_rule.fields.flatten).to include('uid!=euid', 'gid!=egid', 'euid=0', 'egid=0')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_syscall])
      end
    end
  end
end
