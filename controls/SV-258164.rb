control 'SV-258164' do
  title 'The RHEL 8 audit system must audit local events.'
  desc 'Without establishing what type of events occurred, the source of
events, where events occurred, and the outcome of events, it would be difficult
to establish, correlate, and investigate the events leading up to an outage or
attack.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.'
  desc 'check', 'Verify the RHEL 8 Audit Daemon is configured to include local events, with
the following command:

    $ sudo grep local_events /etc/audit/auditd.conf

    local_events = yes

    If the value of the "local_events" option is not set to "yes", or the
line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to audit local events on the system.

Add or update the following line in "/etc/audit/auditd.conf" file:

local_events = yes'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230393'
  tag rid: 'SV-258164r627750_rule'
  tag stig_id: 'RHEL-08-030061'
  tag fix_id: 'F-33037r567926_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe parse_config_file('/etc/audit/auditd.conf') do
    its('local_events') { should eq 'yes' }
  end
end
