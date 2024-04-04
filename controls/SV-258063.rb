control 'SV-258063' do
  title 'RHEL 8 must have the tmux package installed.'
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
  desc 'check', 'Verify RHEL 8 has the "tmux" package installed, by running the following
command:

    $ sudo yum list installed tmux

    tmux.x86.64                     2.7-1.el8
@repository

    If "tmux" is not installed, this is a finding.'
  desc 'fix', 'Configure the operating system to enable a user to initiate a session lock
via tmux.

    Install the "tmux" package, if it is not already installed, by running
the following command:

    $ sudo yum install tmux'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag gid: 'V-244537'
  tag rid: 'SV-258063r743860_rule'
  tag stig_id: 'RHEL-08-020039'
  tag fix_id: 'F-47769r743859_fix'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe package('tmux') do
    it { should be_installed }
  end
end
