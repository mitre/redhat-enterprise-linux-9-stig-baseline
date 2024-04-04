control 'SV-258169' do
  title 'RHEL 8 must resolve audit information before writing to disk.'
  desc 'Without establishing what type of events occurred, the source of
events, where events occurred, and the outcome of events, it would be difficult
to establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Enriched logging aids in making sense of who, what, and when events occur
on a system.  Without this, determining root cause of an event will be much
more difficult.'
  desc 'check', 'Verify the RHEL 8 Audit Daemon is configured to resolve audit information
before writing to disk, with the following command:

    $ sudo grep "log_format" /etc/audit/auditd.conf

    log_format = ENRICHED

    If the "log_format" option is not "ENRICHED", or the line is commented
out, this is a finding.'
  desc 'fix', 'Edit the /etc/audit/auditd.conf file and add or update the "log_format"
option:

    log_format = ENRICHED

    The audit daemon must be restarted for changes to take effect.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230395'
  tag rid: 'SV-258169r627750_rule'
  tag stig_id: 'RHEL-08-030063'
  tag fix_id: 'F-33039r567932_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe parse_config_file('/etc/audit/auditd.conf') do
    its('log_format') { should eq 'ENRICHED' }
  end
end
