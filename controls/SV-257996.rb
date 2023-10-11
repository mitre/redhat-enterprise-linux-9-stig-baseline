control 'SV-257996' do
  title 'RHEL 9 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.'
  desc 'Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.

RHEL 9 utilizes /etc/ssh/sshd_config for configurations of OpenSSH. Within the sshd_config, the product of the values of "ClientAliveInterval" and "ClientAliveCountMax" are used to establish the inactivity threshold. The "ClientAliveInterval" is a timeout interval in seconds, after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. The "ClientAliveCountMax" is the number of client alive messages that may be sent without sshd receiving any messages back from the client. If this threshold is met, sshd will disconnect the client. For more information on these settings and others, refer to the sshd_config man pages.

'
  desc 'check', 'Verify that the "ClientAliveInterval" variable is set to a value of "600" or less by performing the following command:

$ sudo grep -i interval /etc/ssh/sshd_config

ClientAliveInterval 600

If "ClientAliveInterval" does not exist, does not have a value of "600" or less in "/etc/ssh/sshd_config", or is commented out, this is a finding.'
  desc 'fix', 'Note: This setting must be applied in conjunction with RHEL-09-255095 to function correctly.

Configure the SSH server to terminate a user session automatically after the SSH client has been unresponsive for 10 minutes.

Modify or append the following lines in the "/etc/ssh/sshd_config" file:

ClientAliveInterval 600

In order for the changes to take effect, the SSH daemon must be restarted.

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61737r925973_chk'
  tag severity: 'medium'
  tag gid: 'V-257996'
  tag rid: 'SV-257996r925975_rule'
  tag stig_id: 'RHEL-09-255100'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag fix_id: 'F-61661r925974_fix'
  tag satisfies: ['SRG-OS-000126-GPOS-00066', 'SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109', 'SRG-OS-000395-GPOS-00175']
  tag 'documentable'
  tag cci: ['CCI-000879', 'CCI-001133', 'CCI-002361', 'CCI-002891']
  tag nist: ['MA-4 e', 'SC-10', 'AC-12', 'MA-4 (7)']
end
