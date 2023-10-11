control 'SV-257887' do
  title 'RHEL 9 audit tools must have a mode of 0755 or less permissive.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

RHEL 9 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify the audit tools have a mode of "0755" or less with the following command:

$ stat -c "%a %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules

755 /sbin/auditctl
755 /sbin/aureport
755 /sbin/ausearch
750 /sbin/autrace
755 /sbin/auditd
755 /sbin/rsyslogd
755 /sbin/augenrules

If any of the audit tool files have a mode more permissive than "0755", this is a finding.'
  desc 'fix', 'Configure the audit tools to have a mode of "0755" by running the following command:

$ sudo chmod 0755 [audit_tool]

Replace "[audit_tool]" with each audit tool that has a more permissive mode than 0755.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61628r925646_chk'
  tag severity: 'medium'
  tag gid: 'V-257887'
  tag rid: 'SV-257887r925648_rule'
  tag stig_id: 'RHEL-09-232035'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-61552r925647_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
