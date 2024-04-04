control 'SV-257925' do
  title 'RHEL 9 audit tools must be group-owned by root.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data; therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

RHEL 9 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify the audit tools are group owned by "root" with the following command:

$ sudo stat -c "%G %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules

root /sbin/auditctl
root /sbin/aureport
root /sbin/ausearch
root /sbin/autrace
root /sbin/auditd
root /sbin/rsyslogd
root /sbin/augenrules

If any audit tools do not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure the audit tools to be group-owned by "root" by running the following command:

$ sudo chgrp root [audit_tool]

Replace "[audit_tool]" with each audit tool not group-owned by "root".'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag gid: 'V-257925'
  tag rid: 'SV-257925r925762_rule'
  tag stig_id: 'RHEL-09-232225'
  tag fix_id: 'F-61590r925761_fix'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9', 'AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_tools = ['/sbin/auditctl', '/sbin/aureport', '/sbin/ausearch', '/sbin/autrace', '/sbin/auditd', '/sbin/rsyslogd', '/sbin/augenrules']

  failing_tools = audit_tools.reject { |at| file(at).group == 'root' }

  describe 'Audit executables' do
    it 'should be group owned by root' do
      expect(failing_tools).to be_empty, "Failing tools:\n\t- #{failing_tools.join("\n\t- ")}"
    end
  end
end
