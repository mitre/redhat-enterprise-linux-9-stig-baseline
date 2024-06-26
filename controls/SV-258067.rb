control 'SV-258067' do
  title 'RHEL 9 must prevent users from disabling session control mechanisms.'
  desc 'The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 9 must provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'Verify RHEL 9 prevents users from disabling the tmux terminal multiplexer with the following command:

$ grep -i tmux /etc/shells

If any output is produced, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent users from disabling the tmux terminal multiplexer by editing the "/etc/shells" configuration file to remove any instances of tmux.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011', 'SRG-OS-000324-GPOS-00125']
  tag gid: 'V-258067'
  tag rid: 'SV-258067r926188_rule'
  tag stig_id: 'RHEL-09-412030'
  tag fix_id: 'F-61732r926187_fix'
  tag cci: ['CCI-000056', 'CCI-002235']
  tag nist: ['AC-11 b', 'AC-6 (10)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe command('grep -i tmux /etc/shells') do
    its('stdout.strip') { should be_empty }
  end
end
