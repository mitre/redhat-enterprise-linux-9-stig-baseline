control 'SV-258011' do
  title 'The RHEL 8 SSH daemon must prevent remote hosts from connecting to the
proxy display.'
  desc 'When X11 forwarding is enabled, there may be additional exposure to
the server and client displays if the sshd proxy display is configured to
listen on the wildcard address.  By default, sshd binds the forwarding server
to the loopback address and sets the hostname part of the DIPSLAY environment
variable to localhost.  This prevents remote hosts from connecting to the proxy
display.'
  desc 'check', 'Verify the SSH daemon prevents remote hosts from connecting to the proxy display.

Check the SSH X11UseLocalhost setting with the following command:

# sudo grep -ir x11uselocalhost /etc/ssh/sshd_config*
X11UseLocalhost yes

If the "X11UseLocalhost" keyword is set to "no", is missing, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to prevent remote hosts from connecting to the
proxy display.

    Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the
"X11UseLocalhost" keyword and set its value to "yes" (this file may be
named differently or be in a different location if using a version of SSH that
is provided by a third-party vendor):

    X11UseLocalhost yes'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230556'
  tag rid: 'SV-258011r858723_rule'
  tag stig_id: 'RHEL-08-040341'
  tag fix_id: 'F-33200r568415_fix'
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
