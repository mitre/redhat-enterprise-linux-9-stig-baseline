control 'SV-258069' do
  title 'RHEL 8 must limit the number of concurrent sessions to ten for all
accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number
of users and user sessions that utilize an operating system. Limiting the
number of allowed users and sessions per user is helpful in reducing the risks
related to DoS attacks.

    This requirement addresses concurrent sessions for information system
accounts and does not address concurrent sessions by single users via multiple
system accounts. The maximum number of concurrent sessions should be defined
based on mission needs and the operational environment for each system.'
  desc 'check', %q(Verify the operating system limits the number of concurrent sessions to
"10" for all accounts and/or account types by issuing the following command:

    $ sudo grep -r -s '^[^#].*maxlogins' /etc/security/limits.conf
/etc/security/limits.d/*.conf

    * hard maxlogins 10

    This can be set as a global domain (with the * wildcard) but may be set
differently for multiple domains.

    If the "maxlogins" item is missing, commented out, or the value is set
greater than "10" and is not documented with the Information System Security
Officer (ISSO) as an operational requirement for all domains that have the
"maxlogins" item assigned, this is a finding.)
  desc 'fix', 'Configure the operating system to limit the number of concurrent sessions
to "10" for all accounts and/or account types.

    Add the following line to the top of the /etc/security/limits.conf or in a
".conf" file defined in /etc/security/limits.d/:

    * hard maxlogins 10'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag gid: 'V-230346'
  tag rid: 'SV-258069r877399_rule'
  tag stig_id: 'RHEL-08-020024'
  tag fix_id: 'F-32990r619863_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  setting = 'maxlogins'
  expected_value = input('concurrent_sessions_permitted')

  limits_files = command('ls /etc/security/limits.d/*.conf').stdout.strip.split
  limits_files.append('/etc/security/limits.conf')

  # make sure that at least one limits.conf file has the correct setting
  globally_set = limits_files.any? { |lf| !limits_conf(lf).read_params['*'].nil? && limits_conf(lf).read_params['*'].include?(['hard', setting.to_s, expected_value.to_s]) }

  # make sure that no limits.conf file has a value that contradicts the global set
  failing_files = limits_files.select { |lf|
    limits_conf(lf).read_params.values.flatten(1).any? { |l|
      l[1].eql?(setting) && l[2].to_i > expected_value
    }
  }
  describe 'Limits files' do
    it "should limit concurrent sessions to #{expected_value} by default" do
      expect(globally_set).to eq(true), "No global ('*') setting for concurrent sessions found"
    end
    it 'should not have any conflicting settings' do
      expect(failing_files).to be_empty, "Files with incorrect '#{setting}' settings:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
