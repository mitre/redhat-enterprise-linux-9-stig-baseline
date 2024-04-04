control 'SV-258003' do
  title 'The RHEL 8 SSH daemon must not allow GSSAPI authentication, except to fulfill documented and validated mission requirements.'
  desc 'Configuring this setting for the SSH daemon provides additional
assurance that remote logon via SSH will require a password, even in the event
of misconfiguration elsewhere.'
  desc 'check', 'Verify the SSH daemon does not allow GSSAPI authentication with the following command:

$ sudo grep -ir GSSAPIAuthentication  /etc/ssh/sshd_config*

GSSAPIAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, or has not been documented with the ISSO, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to not allow GSSAPI authentication.

    Add the following line in "/etc/ssh/sshd_config", or uncomment the line
and set the value to "no":

    GSSAPIAuthentication no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
  impact 0.0
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244528'
  tag rid: 'SV-258003r858709_rule'
  tag stig_id: 'RHEL-08-010522'
  tag fix_id: 'F-47760r743832_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  setting = 'GSSAPIAuthentication'
  gssapi_authentication = input('sshd_config_values')
  value = gssapi_authentication[setting]

  if virtualization.system.eql?('docker')
    describe 'In a container Environment' do
      if package('openssh-server').installed?
        it 'the OpenSSH Server should be installed when allowed in Docker environment' do
          expect(input('allow_container_openssh_server')).to eq(true), 'OpenSSH Server is installed but not approved for the Docker environment'
        end
      else
        it 'the OpenSSH Server is not installed' do
          skip 'This requirement is not applicable as the OpenSSH Server is not installed in the Docker environment.'
        end
      end
    end
  else
    describe 'The OpenSSH Server configuration' do
      it "has the correct #{setting} configuration" do
        expect(sshd_config.params[setting.downcase]).to cmp(value), "The #{setting} setting in the SSHD config is not correct. Please ensure it set to '#{value}'."
      end
    end
  end
end
