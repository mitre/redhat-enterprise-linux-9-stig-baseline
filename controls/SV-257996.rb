control 'SV-257996' do
  title 'RHEL 8 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.'
  desc 'Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.

RHEL 8 uses /etc/ssh/sshd_config for configurations of OpenSSH. Within the sshd_config, the product of the values of "ClientAliveInterval" and "ClientAliveCountMax" is used to establish the inactivity threshold. The "ClientAliveInterval" is a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. The "ClientAliveCountMax" is the number of client alive messages that may be sent without sshd receiving any messages back from the client. If this threshold is met, sshd will disconnect the client. For more information on these settings and others, refer to the sshd_config man pages.'
  desc 'check', 'Verify the SSH server automatically terminates a user session after the SSH client has been unresponsive for 10 minutes.

Check that the "ClientAliveInterval" variable is set to a value of "600" or less by performing the following command:

     $ sudo grep -ir clientaliveinterval /etc/ssh/sshd_config*

     ClientAliveInterval 600

If "ClientAliveInterval" does not exist, does not have a value of "600" or less in "/etc/ssh/sshd_config" or is commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Note: This setting must be applied in conjunction with RHEL-08-010200 to function correctly.

Configure the SSH server to terminate a user session automatically after the SSH client has been unresponsive for 10 minutes.

Modify or append the following lines in the "/etc/ssh/sshd_config" file:

     ClientAliveInterval 600

For the changes to take effect, the SSH daemon must be restarted.

     $ sudo systemctl restart sshd.service'
  impact 0.0
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000126-GPOS-00066', 'SRG-OS-000279-GPOS-00109']
  tag gid: 'V-244525'
  tag rid: 'SV-257996r917886_rule'
  tag stig_id: 'RHEL-08-010201'
  tag fix_id: 'F-47757r917885_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
  tag 'host'
  tag 'container-conditional'

  setting = 'ClientAliveInterval'
  gssapi_authentication = input('sshd_config_values')
  value = gssapi_authentication[setting]
  openssh_present = package('openssh-server').installed?

  only_if('This requirement is Not Applicable in the container without open-ssh installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !openssh_present)
  }

  if input('allow_container_openssh_server') == false
    describe 'In a container Environment' do
      it 'the OpenSSH Server should be installed only when allowed in a container environment' do
        expect(openssh_present).to eq(false), 'OpenSSH Server is installed but not approved for the container environment'
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
