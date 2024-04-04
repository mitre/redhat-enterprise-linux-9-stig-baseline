control 'SV-258067' do
  title 'RHEL 8 must prevent users from disabling session control mechanisms.'
  desc 'A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined. Rather than be forced to wait for a period of time to expire before
the user session can be locked, RHEL 8 needs to provide users with the ability
to manually invoke a session lock so users can secure their session if it is
necessary to temporarily vacate the immediate physical vicinity.

    Tmux is a terminal multiplexer that enables a number of terminals to be
created, accessed, and controlled from a single screen.  Red Hat endorses tmux
as the recommended session controlling package.'
  desc 'check', 'Verify the operating system prevents users from disabling the tmux terminal
multiplexer with the following command:

    $ sudo grep -i tmux /etc/shells

    If any output is produced, this is a finding.'
  desc 'fix', 'Configure the operating system to prevent users from disabling
the tmux terminal multiplexer by editing the "/etc/shells" configuration file
to remove any instances of tmux.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag gid: 'V-230350'
  tag rid: 'SV-258067r627750_rule'
  tag stig_id: 'RHEL-08-020042'
  tag fix_id: 'F-32994r567797_fix'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  describe command('grep -i tmux /etc/shells') do
    its('stdout.strip') { should be_empty }
  end
end
