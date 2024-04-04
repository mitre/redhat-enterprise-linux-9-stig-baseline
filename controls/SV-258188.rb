control 'SV-258188' do
  title 'Successful/unsuccessful uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls in RHEL 8 must generate an audit record.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "truncate" and "ftruncate" functions are used to truncate a file to a specified length.

The "creat" system call is used to open and possibly create a file or device.
The "open" system call opens a file specified by a pathname. If the specified file does not exist, it may optionally be created by "open".
The "openat" system call opens a file specified by a relative pathname.
The "name_to_handle_at" and "open_by_handle_at" system calls split the functionality of "openat" into two parts: "name_to_handle_at" returns an opaque handle that corresponds to a specified file; "open_by_handle_at" opens the file corresponding to a handle returned by a previous call to "name_to_handle_at" and returns an open file descriptor.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.'
  desc 'check', %q(Verify RHEL 8 generates an audit record upon successful/unsuccessful attempts to use the "truncate", "ftruncate", "creat", "open", "openat", and "open_by_handle_at" system calls by using the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep 'open\|truncate\|creat' /etc/audit/audit.rules

-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access

-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access

If the output does not produce rules containing "-F exit=-EPERM", this is a finding.
If the output does not produce rules containing "-F exit=-EACCES", this is a finding.
If the command does not return an audit rule for "truncate", "ftruncate", "creat", "open", "openat", and "open_by_handle_at" or any of the lines returned are commented out, this is a finding.)
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "truncate", "ftruncate", "creat", "open", "openat", and "open_by_handle_at" system calls by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access

-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000064-GPOS-00033']
  tag gid: 'V-230449'
  tag rid: 'SV-258188r810455_rule'
  tag stig_id: 'RHEL-08-030420'
  tag fix_id: 'F-33093r809304_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
  tag 'host'

  audit_syscalls = ['truncate', 'ftruncate', 'creat', 'open', 'openat', 'open_by_handle_at']

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
