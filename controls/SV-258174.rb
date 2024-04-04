control 'SV-258174' do
  title 'The RHEL 8 Information System Security Officer (ISSO) and System
Administrator (SA) (at a minimum) must have mail aliases to be notified of an
audit processing failure.'
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
  desc 'check', 'Verify that the administrators are notified in the event of an audit
processing failure.

    Check that the "/etc/aliases" file has a defined value for "root".

    $ sudo grep "postmaster:\\s*root$" /etc/aliases

    If the command does not return a line, or the line is commented out, ask
the system administrator to indicate how they and the ISSO are notified of an
audit process failure.  If there is no evidence of the proper personnel being
notified of an audit processing failure, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to notify administrators in the event of an audit
processing failure.

    Add/update the following line in "/etc/aliases":

    postmaster: root'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag gid: 'V-230389'
  tag rid: 'SV-258174r627750_rule'
  tag stig_id: 'RHEL-08-030030'
  tag fix_id: 'F-33033r567914_fix'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  alternative_logging = input('alternative_logging')

  if alternative_logging == true
    describe 'Alternative logging' do
      it 'should handle sysadmin and ISSO notification' do
        expect(alternative_logging).to eq(true)
      end
    end
  else
    describe command('grep "postmaster:\s*root$" /etc/aliases') do
      its('stdout.strip') { should match(/postmaster:\s*root/) }
    end
  end
end
