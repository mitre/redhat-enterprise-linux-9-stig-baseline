control 'SV-258153' do
  title 'The RHEL 8 System must take appropriate action when an audit
processing failure occurs.'
  desc 'It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without this
notification, the security personnel may be unaware of an impending failure of
the audit capability, and system operation may be adversely affected.

    Audit processing failures include software/hardware errors, failures in the
audit capturing mechanisms, and audit storage capacity being reached or
exceeded.

    This requirement applies to each audit data storage repository (i.e.,
distinct information system component where audit records are stored), the
centralized audit storage capacity of organizations (i.e., all audit data
storage repositories combined), or both.'
  desc 'check', 'Verify RHEL 8 takes the appropriate action when an audit processing failure
occurs.

    Check that RHEL 8 takes the appropriate action when an audit processing
failure occurs with the following command:

    $ sudo grep disk_error_action /etc/audit/auditd.conf

    disk_error_action = HALT

    If the value of the "disk_error_action" option is not "SYSLOG",
"SINGLE", or "HALT", or the line is commented out, ask the system
administrator to indicate how the system takes appropriate action when an audit
process failure occurs.  If there is no evidence of appropriate action, this is
a finding.'
  desc 'fix', 'Configure RHEL 8 to shut down by default upon audit failure (unless
availability is an overriding concern).

    Add or update the following line (depending on configuration
"disk_error_action" can be set to "SYSLOG" or "SINGLE" depending on
configuration) in "/etc/audit/auditd.conf" file:

    disk_error_action = HALT

    If availability has been determined to be more important, and this decision
is documented with the ISSO, configure the operating system to notify system
administration staff and ISSO staff in the event of an audit processing failure
by setting the "disk_error_action" to "SYSLOG".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag gid: 'V-230390'
  tag rid: 'SV-258153r627750_rule'
  tag stig_id: 'RHEL-08-030040'
  tag fix_id: 'F-33034r567917_fix'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  disk_error_action = input('disk_error_action').map(&:upcase)

  describe auditd_conf do
    its('disk_error_action.upcase') { should be_in disk_error_action }
  end
end
