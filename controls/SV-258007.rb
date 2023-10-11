control 'SV-258007' do
  title 'RHEL 9 SSH daemon must disable remote X connections for interactive users.'
  desc 'When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address.  By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the DISPLAY environment variable to localhost. This prevents remote hosts from connecting to the proxy display.'
  desc 'check', 'Verify the SSH daemon does not allow X11Forwarding with the following command:

$ sudo grep -ir x11for  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*

X11forwarding no

If the value is returned as "yes", the returned line is commented out, or no output is returned, and X11 forwarding is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to not allow X11 forwarding.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes":

X11forwarding no

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61748r926006_chk'
  tag severity: 'medium'
  tag gid: 'V-258007'
  tag rid: 'SV-258007r926008_rule'
  tag stig_id: 'RHEL-09-255155'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61672r926007_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
