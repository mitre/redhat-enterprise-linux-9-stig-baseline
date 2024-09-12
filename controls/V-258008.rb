control 'V-258008' do
  title 'RHEL 9 SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', %q(Verify the SSH daemon performs strict mode checking of home directory configuration files with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*strictmodes'

StrictModes yes

If the "StrictModes" keyword is set to "no", the returned line is commented out, or no output is returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to perform strict mode checking of home directory configuration files.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes":

StrictModes yes

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61749r952211_chk'
  tag severity: 'medium'
  tag gid: 'V-258008'
  tag rid: 'SV-258008r991589_rule'
  tag stig_id: 'RHEL-09-255160'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61673r926010_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
