control 'V-258006' do
  title 'RHEL 9 SSH daemon must not allow known hosts authentication.'
  desc 'Configuring the IgnoreUserKnownHosts setting for the SSH daemon provides additional assurance that remote login via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(Verify the SSH daemon does not allow known hosts authentication with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*ignoreuserknownhosts'

IgnoreUserKnownHosts yes

If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to not allow known hosts authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes":

IgnoreUserKnownHosts yes

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61747r952207_chk'
  tag severity: 'medium'
  tag gid: 'V-258006'
  tag rid: 'SV-258006r991589_rule'
  tag stig_id: 'RHEL-09-255150'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61671r926004_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
