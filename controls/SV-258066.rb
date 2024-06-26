control 'SV-258066' do
  title 'RHEL 9 must automatically lock command line user sessions after 15 minutes of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not logout because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, tmux can be configured to identify when a user's session has idled and take action to initiate a session lock."
  desc 'check', 'Verify RHEL 9 initiates a session lock after 15 minutes of inactivity.

Check the value of the system inactivity timeout with the following command:

$ grep -i lock-after-time /etc/tmux.conf

set -g lock-after-time 900

If "lock-after-time" is not set to "900" or less in the global tmux configuration file to enforce session lock after inactivity, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enforce session lock after a period of 15 minutes of inactivity by adding the following line to the "/etc/tmux.conf" global configuration file:

set -g lock-after-time 900'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012']
  tag gid: 'V-258066'
  tag rid: 'SV-258066r926185_rule'
  tag stig_id: 'RHEL-09-412025'
  tag fix_id: 'F-61731r926184_fix'
  tag cci: ['CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 a', 'AC-11 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  timeout = command('grep -i lock-after-time /etc/tmux.conf').stdout.strip.match(/lock-after-time\s+(?<timeout>\d+)/)
  expected_timeout = input('system_activity_timeout')

  describe 'tmux settings' do
    it 'should set lock-after-time' do
      expect(timeout).to_not be_nil, 'lock-after-time not set'
    end
    unless timeout.nil?
      it "should lock the session after #{expected_timeout} seconds" do
        expect(timeout['timeout'].to_i).to cmp <= expected_timeout
      end
    end
  end
end
