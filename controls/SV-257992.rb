control 'SV-257992' do
  title 'RHEL 9 must not allow a noncertificate trusted host SSH logon to the system.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.'
  desc 'check', 'Verify the operating system does not allow a noncertificate trusted host SSH logon to the system with the following command:

$ sudo grep -i hostbasedauthentication /etc/ssh/sshd_config

HostbasedAuthentication no

If the "HostbasedAuthentication" keyword is not set to "no", is missing, or is commented out, this is a finding.

If the required value is not set, this is a finding.'
  desc 'fix', 'To configure RHEL 9 to not allow a noncertificate trusted host SSH logon to the system add or modify the following line in "/etc/ssh/sshd_config".

HostbasedAuthentication no

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61733r925961_chk'
  tag severity: 'medium'
  tag gid: 'V-257992'
  tag rid: 'SV-257992r925963_rule'
  tag stig_id: 'RHEL-09-255080'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-61657r925962_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
