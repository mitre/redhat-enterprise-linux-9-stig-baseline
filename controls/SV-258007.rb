control 'SV-258007' do
  title 'RHEL 9 SSH daemon must disable remote X connections for interactive users.'
  desc 'When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address.  By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the DISPLAY environment variable to localhost. This prevents remote hosts from connecting to the proxy display.'
  desc 'check', %q(Verify the SSH daemon does not allow X11Forwarding with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*x11forwarding'

X11forwarding no

If the value is returned as "yes", the returned line is commented out, or no output is returned, and X11 forwarding is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to not allow X11 forwarding.

Add the following line to "/etc/ssh/sshd_config" or to a file in "/etc/ssh/sshd_config.d", or uncomment the line and set the value to "no":

X11forwarding no

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258007'
  tag rid: 'SV-258007r1045073_rule'
  tag stig_id: 'RHEL-09-255155'
  tag fix_id: 'F-61672r1045072_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  describe sshd_config do
    its('X11Forwarding') { should cmp 'no' }
  end
end
