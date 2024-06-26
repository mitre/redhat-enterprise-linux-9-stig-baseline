control 'SV-258009' do
  title 'RHEL 9 SSH daemon must display the date and time of the last successful account logon upon an SSH logon.'
  desc 'Providing users feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Verify the SSH daemon provides users with feedback on when account accesses last occurred with the following command:

$ sudo grep -ir printlast  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*

PrintLastLog yes

If the "PrintLastLog" keyword is set to "no", the returned line is commented out, or no output is returned, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to provide users with feedback on when account accesses last occurred.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes":

PrintLastLog yes

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258009'
  tag rid: 'SV-258009r926014_rule'
  tag stig_id: 'RHEL-09-255165'
  tag fix_id: 'F-61674r926013_fix'
  tag cci: ['CCI-000366', 'CCI-000052']
  tag nist: ['CM-6 b', 'AC-9']
  tag 'host'
  tag 'container-conditional'

  if virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else
    describe sshd_config do
      its('PrintLastLog') { should cmp 'yes' }
    end
  end
end
