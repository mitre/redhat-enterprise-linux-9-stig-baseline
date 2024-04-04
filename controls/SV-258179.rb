control 'SV-258179' do
  title 'The RHEL 8 audit system must be configured to audit any usage of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

"Setxattr" is a system call used to set an extended attribute value.
"Fsetxattr" is a system call used to set an extended attribute value. This is used to set extended attributes on a file.
"Lsetxattr" is a system call used to set an extended attribute value. This is used to set extended attributes on a symbolic link.
"Removexattr" is a system call that removes extended attributes.
"Fremovexattr" is a system call that removes extended attributes. This is used for removal of extended attributes from a file.
"Lremovexattr" is a system call that removes extended attributes. This is used for removal of extended attributes from symbolic links.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.'
  desc 'check', 'Verify if RHEL 8 is configured to audit the execution of the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" system calls by running the following command:

$ sudo grep xattr /etc/audit/audit.rules

-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod

If the command does not return an audit rule for "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" or any of the lines returned are commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to audit the execution of the "setxattr", "fsetxattr", "lsetxattr", "removexattr", "fremovexattr", and "lremovexattr" system calls by adding or updating the following lines to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000474-GPOS-00219', 'SRG-OS-000466-GPOS-00210']
  tag gid: 'V-230413'
  tag rid: 'SV-258179r810463_rule'
  tag stig_id: 'RHEL-08-030200'
  tag fix_id: 'F-33057r809294_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
  tag 'host'

  audit_syscalls = ['setxattr', 'fsetxattr', 'lsetxattr', 'removexattr', 'fremovexattr', 'lremovexattr']

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
