control 'SV-258009' do
  title 'RHEL 8 must display the date and time of the last successful account
logon upon an SSH logon.'
  desc 'Providing users with feedback on when account accesses via SSH last
occurred facilitates user recognition and reporting of unauthorized account
use.'
  desc 'check', 'Verify SSH provides users with feedback on when account accesses last occurred with the following command:

$ sudo grep -ir printlastlog /etc/ssh/sshd_config*

PrintLastLog yes

If the "PrintLastLog" keyword is set to "no", is missing, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure SSH to provide users with feedback on when account accesses last
occurred by setting the required configuration options in "/etc/pam.d/sshd"
or in the "sshd_config" file used by the system ("/etc/ssh/sshd_config"
will be used in the example) (this file may be named differently or be in a
different location if using a version of SSH that is provided by a third-party
vendor).

    Modify the "PrintLastLog" line in "/etc/ssh/sshd_config" to match the
following:

    PrintLastLog yes

    The SSH service must be restarted for changes to "sshd_config" to take
effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230382'
  tag rid: 'SV-258009r858717_rule'
  tag stig_id: 'RHEL-08-020350'
  tag fix_id: 'F-33026r567893_fix'
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
