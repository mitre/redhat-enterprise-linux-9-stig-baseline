control 'SV-257962' do
  title 'RHEL 9 must use reverse path filtering on all IPv4 interfaces.'
  desc 'Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface on which they were received. It must not be used on systems that are routers for complicated networks, but is helpful for end hosts and routers serving small networks.'
  desc 'check', %q(Verify RHEL 9 uses reverse path filtering on all IPv4 interfaces with the following commands:

$ sysctl net.ipv4.conf.all.rp_filter

net.ipv4.conf.all.rp_filter = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F net.ipv4.conf.all.rp_filter | tail -1

net.ipv4.conf.all.rp_filter = 1

If "net.ipv4.conf.all.rp_filter" is not set to "1" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to use reverse path filtering on all IPv4 interfaces. 

Add or edit the following line in a single system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.rp_filter = 1

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61703r925871_chk'
  tag severity: 'medium'
  tag gid: 'V-257962'
  tag rid: 'SV-257962r925873_rule'
  tag stig_id: 'RHEL-09-253035'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61627r925872_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
