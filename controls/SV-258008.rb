control 'SV-258008' do
  title 'The RHEL 8 SSH daemon must perform strict mode checking of home
directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration
files, they may be able to log on to the system as another user.'
  desc 'check', 'Verify the SSH daemon performs strict mode checking of home directory configuration files with the following command:

$ sudo grep -ir strictmodes /etc/ssh/sshd_config*

StrictModes yes

If "StrictModes" is set to "no", is missing, or the returned line is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure SSH to perform strict mode checking of home directory
configuration files. Uncomment the "StrictModes" keyword in
"/etc/ssh/sshd_config" and set the value to "yes":

    StrictModes yes

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230288'
  tag rid: 'SV-258008r858701_rule'
  tag stig_id: 'RHEL-08-010500'
  tag fix_id: 'F-32932r567611_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  describe sshd_config do
    its('StrictModes') { should cmp 'yes' }
  end
end
