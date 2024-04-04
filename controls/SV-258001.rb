control 'SV-258001' do
  title 'The RHEL 8 SSH public host key files must have mode 0644 or less
permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH
service may be compromised.'
  desc 'check', 'Verify the SSH public host key files have mode "0644" or less permissive
with the following command:

    $ sudo ls -l /etc/ssh/*.pub

    -rw-r--r-- 1 root root 618 Nov 28 06:43 ssh_host_dsa_key.pub
    -rw-r--r-- 1 root root 347 Nov 28 06:43 ssh_host_key.pub
    -rw-r--r-- 1 root root 238 Nov 28 06:43 ssh_host_rsa_key.pub

    If any key.pub file has a mode more permissive than "0644", this is a
finding.

    Note: SSH public key files may be found in other directories on the system
depending on the installation.'
  desc 'fix', 'Change the mode of public host key files under "/etc/ssh" to "0644"
with the following command:

    $ sudo chmod 0644 /etc/ssh/*key.pub

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230286'
  tag rid: 'SV-258001r627750_rule'
  tag stig_id: 'RHEL-08-010480'
  tag fix_id: 'F-32930r567605_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  ssh_host_key_dirs = input('ssh_host_key_dirs').join(' ')
  pub_keys = command("find #{ssh_host_key_dirs} -xdev -name '*.pub'").stdout.split("\n")
  mode = input('ssh_pub_key_mode')
  failing_keys = pub_keys.select { |key| file(key).more_permissive_than?(mode) }

  describe 'All SSH public keys on the filesystem' do
    it "should be less permissive than #{mode}" do
      expect(failing_keys).to be_empty, "Failing keyfiles:\n\t- #{failing_keys.join("\n\t- ")}"
    end
  end
end
