control 'SV-258000' do
  title 'The RHEL 8 SSH private host key files must have mode 0640 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the
host could be impersonated.'
  desc 'check', 'Verify the SSH private host key files have mode "0640" or less permissive with the following command:

     $ sudo ls -l /etc/ssh/ssh_host*key

     -rw-r----- 1 root ssh_keys 668 Nov 28 06:43 ssh_host_dsa_key
     -rw-r----- 1 root ssh_keys 582 Nov 28 06:43 ssh_host_key
     -rw-r----- 1 root ssh_keys 887 Nov 28 06:43 ssh_host_rsa_key

If any private host key file has a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Configure the mode of SSH private host key files under "/etc/ssh" to "0640" with the following command:

     $ sudo chmod 0640 /etc/ssh/ssh_host*key

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

     $ sudo systemctl restart sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230287'
  tag rid: 'SV-258000r880714_rule'
  tag stig_id: 'RHEL-08-010490'
  tag fix_id: 'F-32931r880713_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  ssh_host_key_dirs = input('ssh_host_key_dirs').join(' ')
  priv_keys = command("find #{ssh_host_key_dirs} -xdev -name '*.pem'").stdout.split("\n")
  mode = input('ssh_private_key_mode')
  failing_keys = priv_keys.select { |key| file(key).more_permissive_than?(mode) }

  describe 'All SSH private keys on the filesystem' do
    it "should be less permissive than #{mode}" do
      expect(failing_keys).to be_empty, "Failing keyfiles:\n\t- #{failing_keys.join("\n\t- ")}"
    end
  end
end
