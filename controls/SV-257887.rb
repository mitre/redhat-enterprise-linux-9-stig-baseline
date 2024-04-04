control 'SV-257887' do
  title 'RHEL 8 audit tools must have a mode of 0755 or less permissive.'
  desc 'Protecting audit information also includes identifying and protecting
the tools used to view and manipulate log data. Therefore, protecting audit
tools is necessary to prevent unauthorized operation on audit information.

    RHEL 8 systems providing tools to interface with audit information will
leverage user permissions and roles identifying the user accessing the tools,
and the corresponding rights the user enjoys, to make access decisions
regarding the access to audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.'
  desc 'check', 'Verify the audit tools are protected from unauthorized access, deletion, or
modification by checking the permissive mode.

    Check the octal permission of each audit tool by running the following
command:

    $ sudo stat -c "%a %n" /sbin/auditctl /sbin/aureport /sbin/ausearch
/sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules

    755 /sbin/auditctl
    755 /sbin/aureport
    755 /sbin/ausearch
    750 /sbin/autrace
    755 /sbin/auditd
    755 /sbin/rsyslogd
    755 /sbin/augenrules

    If any of the audit tools has a mode more permissive than "0755", this is
a finding.'
  desc 'fix', 'Configure the audit tools to be protected from unauthorized access by
setting the correct permissive mode using the following command:

    $ sudo chmod 0755 [audit_tool]

    Replace "[audit_tool]" with the audit tool that does not have the correct
permissive mode.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag gid: 'V-230472'
  tag rid: 'SV-257887r627750_rule'
  tag stig_id: 'RHEL-08-030620'
  tag fix_id: 'F-33116r568163_fix'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9', 'AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  audit_tools = ['/sbin/auditctl', '/sbin/aureport', '/sbin/ausearch', '/sbin/autrace', '/sbin/auditd', '/sbin/rsyslogd', '/sbin/augenrules']

  failing_tools = audit_tools.select { |at| file(at).more_permissive_than?(input('audit_tool_mode')) }

  describe 'Audit executables' do
    it "should be no more permissive than '#{input('audit_tool_mode')}'" do
      expect(failing_tools).to be_empty, "Failing tools:\n\t- #{failing_tools.join("\n\t- ")}"
    end
  end
end
