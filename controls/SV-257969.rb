control 'SV-257969' do
  title 'RHEL 9 must not allow interfaces to perform Internet Control Message Protocol (ICMP) redirects by default.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table possibly revealing portions of the network topology.

The ability to send ICMP redirects is only appropriate for systems acting as routers."
  desc 'check', %q(Verify RHEL 9 does not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Check the value of the "default send_redirects" variables with the following command:

$ sysctl net.ipv4.conf.default.send_redirects

net.ipv4.conf.default.send_redirects=0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv4.conf.default.send_redirects | tail -1

net.ipv4.conf.default.send_redirects = 0

If "net.ipv4.conf.default.send_redirects" is not set to "0" and is not documented with the information system security officer (ISSO) as an operational requirement or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.default.send_redirects = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61710r925892_chk'
  tag severity: 'medium'
  tag gid: 'V-257969'
  tag rid: 'SV-257969r925894_rule'
  tag stig_id: 'RHEL-09-253070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61634r925893_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
