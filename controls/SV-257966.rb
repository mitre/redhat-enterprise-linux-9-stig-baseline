control 'SV-257966' do
  title 'RHEL 9 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.

Ignoring ICMP echo requests (pings) sent to broadcast or multicast addresses makes the system slightly more difficult to enumerate on the network.'
  desc 'check', %q(Verify RHEL 9 does not respond to ICMP echoes sent to a broadcast address.

Check the value of the "icmp_echo_ignore_broadcasts" variable with the following command:

$ sysctl net.ipv4.icmp_echo_ignore_broadcasts

net.ipv4.icmp_echo_ignore_broadcasts = 1

If the returned line does not have a value of "1", a line is not returned, or the retuned line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|$)' | grep -F net.ipv4.icmp_echo_ignore_broadcasts | tail -1

net.ipv4.icmp_echo_ignore_broadcasts = 1

If "net.ipv4.icmp_echo_ignore_broadcasts" is not set to "1" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not respond to IPv4 ICMP echoes sent to a broadcast address.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.icmp_echo_ignore_broadcasts = 1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61707r925883_chk'
  tag severity: 'medium'
  tag gid: 'V-257966'
  tag rid: 'SV-257966r925885_rule'
  tag stig_id: 'RHEL-09-253055'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61631r925884_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
