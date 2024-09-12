control 'V-257924' do
  title 'RHEL 9 audit tools must be owned by root.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

RHEL 9 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify the audit tools are owned by "root" with the following command:

$ sudo stat -c "%U %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules

root /sbin/auditctl
root /sbin/aureport
root /sbin/ausearch
root /sbin/autrace
root /sbin/auditd
root /sbin/rsyslogd
root /sbin/augenrules

If any audit tools do not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure the audit tools to be owned by "root" by running the following command:

$ sudo chown root [audit_tool]

Replace "[audit_tool]" with each audit tool not owned by "root".'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61665r925757_chk'
  tag severity: 'medium'
  tag gid: 'V-257924'
  tag rid: 'SV-257924r991557_rule'
  tag stig_id: 'RHEL-09-232220'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-61589r925758_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
