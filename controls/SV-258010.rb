control 'SV-258010' do
  title 'RHEL 9 SSH daemon must be configured to use privilege separation.'
  desc 'SSH daemon privilege separation causes the SSH process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the nonprivileged section.'
  desc 'check', 'Verify the SSH daemon performs privilege separation with the following command:

$ sudo grep -ir usepriv  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*

UsePrivilegeSeparation sandbox

If the "UsePrivilegeSeparation" keyword is set to "no", the returned line is commented out, or no output is returned, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to perform privilege separation.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes" or "sandbox":

UsePrivilegeSeparation sandbox

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61751r926015_chk'
  tag severity: 'medium'
  tag gid: 'V-258010'
  tag rid: 'SV-258010r926017_rule'
  tag stig_id: 'RHEL-09-255170'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61675r926016_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('UsePrivilegeSeparation') { should be_in ['sandbox', 'yes'] }
  end
end
