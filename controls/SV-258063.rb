control 'SV-258063' do
  title 'RHEL 9 must have the tmux package installed.'
  desc 'Tmux is a terminal multiplexer that enables a number of terminals to be created, accessed, and controlled from a single screen. Red Hat endorses tmux as the recommended session controlling package.

'
  desc 'check', 'Verify that RHEL 9 has the tmux package installed with the following command:

$ sudo dnf list --installed tmux

Example output:

tmux.x86_64          3.2a-4.el9

If the "tmux" package is not installed, this is a finding.'
  desc 'fix', 'The tmux package can be installed with the following command:
 
$ sudo dnf install tmux'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61804r926174_chk'
  tag severity: 'medium'
  tag gid: 'V-258063'
  tag rid: 'SV-258063r926176_rule'
  tag stig_id: 'RHEL-09-412010'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-61728r926175_fix'
  tag satisfies: ['SRG-OS-000030-GPOS-00011', 'SRG-OS-000028-GPOS-00009']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a']
end
