control 'SV-257974' do
  title 'RHEL 9 must not enable IPv6 packet forwarding unless the system is a router.'
  desc 'IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers.'
  desc 'check', %q(Verify RHEL 9 is not performing IPv6 packet forwarding, unless the system is a router.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check that IPv6 forwarding is disabled using the following commands:

$ sysctl net.ipv6.conf.all.forwarding

net.ipv6.conf.all.forwarding = 0

If the IPv6 forwarding value is not "0" and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv6.conf.all.forwarding | tail -1

net.ipv6.conf.all.forwarding = 0

If "net.ipv6.conf.all.forwarding" is not set to "0" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to not allow IPv6 packet forwarding, unless the system is a router.

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.all.forwarding = 0

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61715r925907_chk'
  tag severity: 'medium'
  tag gid: 'V-257974'
  tag rid: 'SV-257974r925909_rule'
  tag stig_id: 'RHEL-09-254025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61639r925908_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
