control 'SV-258059' do
  title 'The root account must be the only account having unrestricted access to RHEL 9 system.'
  desc 'An account has root authority if it has a user identifier (UID) of "0". Multiple accounts with a UID of "0" afford more opportunity for potential intruders to guess a password for a privileged account. Proper configuration of sudo is recommended to afford multiple system administrators access to root privileges in an accountable manner.'
  desc 'check', %q(Verify that only the "root" account has a UID "0" assignment with the following command:

$ awk -F: '$3 == 0 {print $1}' /etc/passwd

root

If any accounts other than "root" have a UID of "0", this is a finding.)
  desc 'fix', 'Change the UID of any account on the system, other than root, that has a UID of "0". 

If the account is associated with system commands or applications, the UID should be changed to one greater than "0" but less than "1000". Otherwise, assign a UID of greater than "1000" that has not already been assigned.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61800r926162_chk'
  tag severity: 'high'
  tag gid: 'V-258059'
  tag rid: 'SV-258059r926164_rule'
  tag stig_id: 'RHEL-09-411100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61724r926163_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
