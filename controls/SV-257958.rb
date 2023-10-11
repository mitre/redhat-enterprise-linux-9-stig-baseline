control 'SV-257958' do
  title 'RHEL 9 must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.

This feature of the IPv4 protocol has few legitimate uses. It should be disabled unless absolutely required."
  desc 'check', %q(Verify RHEL 9 will not accept IPv4 ICMP redirect messages.

Check the value of the all "accept_redirects" variables with the following command:

$ sysctl net.ipv4.conf.all.accept_redirects

net.ipv4.conf.all.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv4.conf.all.accept_redirects | tail -1

net.ipv4.conf.all.accept_redirects = 0

If "net.ipv4.conf.all.accept_redirects" is not set to "0" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to ignore IPv4 ICMP redirect messages.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.accept_redirects = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61699r925859_chk'
  tag severity: 'medium'
  tag gid: 'V-257958'
  tag rid: 'SV-257958r925861_rule'
  tag stig_id: 'RHEL-09-253015'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61623r925860_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
