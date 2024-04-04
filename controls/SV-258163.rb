control 'SV-258163' do
  title 'The RHEL 8 System Administrator (SA) and Information System Security
Officer (ISSO) (at a minimum) must be alerted of an audit processing failure
event.'
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
  desc 'check', 'Verify that the SA and ISSO (at a minimum) are notified in the event of an
audit processing failure.

    Check that RHEL 8 notifies the SA and ISSO (at a minimum) in the event of
an audit processing failure with the following command:

    $ sudo grep action_mail_acct /etc/audit/auditd.conf

    action_mail_acct = root

    If the value of the "action_mail_acct" keyword is not set to "root"
and/or other accounts for security personnel, the "action_mail_acct" keyword
is missing, or the retuned line is commented out, ask the system administrator
to indicate how they and the ISSO are notified of an audit process failure.  If
there is no evidence of the proper personnel being notified of an audit
processing failure, this is a finding.'
  desc 'fix', 'Configure "auditd" service to notify the SA and ISSO in the event of an
audit processing failure.

    Edit the following line in "/etc/audit/auditd.conf" to ensure that
administrators are notified via email for those situations:

    action_mail_acct = root'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag gid: 'V-230388'
  tag rid: 'SV-258163r627750_rule'
  tag stig_id: 'RHEL-08-030020'
  tag fix_id: 'F-33032r567911_fix'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe auditd_conf do
    its('action_mail_acct') { should cmp 'root' }
  end
end
