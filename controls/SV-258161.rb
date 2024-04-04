control 'SV-258161' do
  title 'RHEL 8 must label all off-loaded audit logs before sending them to the
central log server.'
  desc 'Without establishing what type of events occurred, the source of
events, where events occurred, and the outcome of events, it would be difficult
to establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Enriched logging is needed to determine who, what, and when events occur on
a system.  Without this, determining root cause of an event will be much more
difficult.

    When audit logs are not labeled before they are sent to a central log
server, the audit data will not be able to be analyzed and tied back to the
correct system.'
  desc 'check', 'Verify the RHEL 8 Audit Daemon is configured to label all off-loaded audit
logs, with the following command:

    $ sudo grep "name_format" /etc/audit/auditd.conf

    name_format = hostname

    If the "name_format" option is not "hostname", "fqd", or "numeric",
or the line is commented out, this is a finding.'
  desc 'fix', 'Edit the /etc/audit/auditd.conf file and add or update the "name_format"
option:

    name_format = hostname

    The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag gid: 'V-230394'
  tag rid: 'SV-258161r877390_rule'
  tag stig_id: 'RHEL-08-030062'
  tag fix_id: 'F-33038r567929_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe parse_config_file('/etc/audit/auditd.conf') do
    its('name_format') { should match(/^hostname$|^fqd$|^numeric$/i) }
  end
end
