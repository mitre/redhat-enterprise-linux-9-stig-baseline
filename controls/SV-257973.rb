control 'SV-257973' do
  title 'RHEL 9 must not forward IPv6 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.'
  desc 'check', %q(Verify RHEL 9 does not accept IPv6 source-routed packets.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the accept source route variable with the following command:

$ sysctl net.ipv6.conf.all.accept_source_route

net.ipv6.conf.all.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' |  grep -F net.ipv6.conf.all.accept_source_route | tail -1

net.ipv6.conf.all.accept_source_route = 0

If "net.ipv6.conf.all.accept_source_route" is not set to "0" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not forward IPv6 source-routed packets.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.all.accept_source_route = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61714r925904_chk'
  tag severity: 'medium'
  tag gid: 'V-257973'
  tag rid: 'SV-257973r925906_rule'
  tag stig_id: 'RHEL-09-254020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61638r925905_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
