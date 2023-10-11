control 'SV-258065' do
  title 'RHEL 9 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for command line sessions.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, RHEL 9 must provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.'
  desc 'check', %q(Verify RHEL 9 enables the user to initiate a session lock with the following command:

$ sudo grep -Ei 'lock-command|lock-session' /etc/tmux.conf

set -g lock-command vlock
bind X lock-session

If the "lock-command" is not set and "lock-session" is not bound to a specific keyboard key in the global settings, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to enable a user to manually initiate a session lock via tmux. This configuration binds the uppercase letter "X" to manually initiate a session lock after the prefix key "Ctrl + b" has been sent. The complete key sequence is thus "Ctrl + b" then "Shift + x" to lock tmux.

Create a global configuration file "/etc/tmux.conf" and add the following lines:

set -g lock-command vlock
bind X lock-session

Reload tmux configuration to take effect. This can be performed in tmux while it is running:

$ tmux source-file /etc/tmux.conf'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61806r926180_chk'
  tag severity: 'medium'
  tag gid: 'V-258065'
  tag rid: 'SV-258065r926182_rule'
  tag stig_id: 'RHEL-09-412020'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-61730r926181_fix'
  tag 'documentable'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
