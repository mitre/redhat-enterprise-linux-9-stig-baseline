control 'SV-258011' do
  title 'RHEL 9 SSH daemon must prevent remote hosts from connecting to the proxy display.'
  desc 'When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address. By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the "DISPLAY" environment variable to localhost. This prevents remote hosts from connecting to the proxy display.'
  desc 'check', %q(Verify the SSH daemon prevents remote hosts from connecting to the proxy display with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*x11uselocalhost'

X11UseLocalhost yes

If the "X11UseLocalhost" keyword is set to "no", is missing, or is commented out, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to prevent remote hosts from connecting to the proxy display.

Add the following line to "/etc/ssh/sshd_config" or to a file in "/etc/ssh/sshd_config.d", or uncomment the line and set the value to "yes":

X11UseLocalhost yes

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258011'
  tag rid: 'SV-258011r1045079_rule'
  tag stig_id: 'RHEL-09-255175'
  tag fix_id: 'F-61676r1045078_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  describe sshd_config do
    its('X11UseLocalhost') { should cmp 'yes' }
  end
end
