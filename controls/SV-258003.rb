control 'SV-258003' do
  title 'RHEL 9 SSH daemon must not allow GSSAPI authentication.'
  desc "Generic Security Service Application Program Interface (GSSAPI) authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system."
  desc 'check', 'Verify the SSH daemon does not allow GSSAPI authentication with the following command:

$ sudo grep -ir gssapiauth  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*

GSSAPIAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, and the use of GSSAPI authentication has not been documented with the information system security officer (ISSO), this is a finding.

If the required value is not set, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to not allow GSSAPI authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "no":

GSSAPIAuthentication no

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag gid: 'V-258003'
  tag rid: 'SV-258003r925996_rule'
  tag stig_id: 'RHEL-09-255135'
  tag fix_id: 'F-61668r925995_fix'
  tag cci: ['CCI-000366', 'CCI-001813']
  tag nist: ['CM-6 b', 'CM-5 (1) (a)']
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
