control 'SV-258064' do
  title 'RHEL 9 must ensure session control is automatically started at shell initialization.'
  desc 'Tmux is a terminal multiplexer that enables a number of terminals to be created, accessed, and controlled from a single screen. Red Hat endorses tmux as the recommended session controlling package.

'
  desc 'check', 'Verify RHEL 9 shell initialization file is configured to start each shell with the tmux terminal multiplexer.

Determine the location of the tmux script with the following command:

$ sudo grep tmux /etc/bashrc /etc/profile.d/*

/etc/profile.d/tmux.sh:  case "$name" in (sshd|login) exec tmux ;; esac

Review the tmux script by using the following example:

$ cat /etc/profile.d/tmux.sh

If [ "$PS1" ]; then
parent=$(ps -o ppid= -p $$)
name=$(ps -o comm= -p $parent)
case "$name" in (sshd|login) tmux ;; esac
fi

If the shell file is not configured as the example above, is commented out, or is missing, this is a finding.

Determine if tmux is currently running with the following command:

$ sudo ps all | grep tmux | grep -v grep

If the command does not produce output, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to initialize the tmux terminal multiplexer as each shell is called by adding the following to file "/etc/profile.d/tmux.sh":

if [ "$PS1" ]; then
    parent=$(ps -o ppid= -p $$)
    name=$(ps -o comm= -p $parent)
    case "$name" in sshd|login) tmux ;; esac
fi'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61805r926177_chk'
  tag severity: 'medium'
  tag gid: 'V-258064'
  tag rid: 'SV-258064r926179_rule'
  tag stig_id: 'RHEL-09-412015'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-61729r926178_fix'
  tag satisfies: ['SRG-OS-000031-GPOS-00012', 'SRG-OS-000028-GPOS-00009']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000060']
  tag nist: ['AC-11 b', 'AC-11 (1)']
end
