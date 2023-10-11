control 'SV-257959' do
  title 'RHEL 9 must not forward Internet Protocol version 4 (IPv4) source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routerd traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.

Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It must be disabled unless it is absolutely required.'
  desc 'check', %q(Verify RHEL 9 will not accept IPv4 source-routed packets.

Check the value of the all "accept_source_route" variables with the following command:

$ sysctl net.ipv4.conf.all.accept_source_route

net.ipv4.conf.all.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv4.conf.all.accept_source_route | tail -1

net.ipv4.conf.all.accept_source_route = 0

If "net.ipv4.conf.all.accept_source_route" is not set to "0" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to ignore IPv4 source-routed packets.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.accept_source_route = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61700r925862_chk'
  tag severity: 'medium'
  tag gid: 'V-257959'
  tag rid: 'SV-257959r925864_rule'
  tag stig_id: 'RHEL-09-253020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61624r925863_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
