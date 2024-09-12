control 'SV-257939' do
  title 'RHEL 9 must protect against or limit the effects of denial-of-service (DoS) attacks by ensuring rate-limiting measures on impacted network interfaces are implemented.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of RHEL 9 to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exists to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Verify "nftables" is configured to allow rate limits on any connection to the system with the following command:

$ sudo grep -i firewallbackend /etc/firewalld/firewalld.conf

# FirewallBackend
FirewallBackend=nftables

If the "nftables" is not set as the "FirewallBackend" default, this is a finding.'
  desc 'fix', 'Configure "nftables" to be the default "firewallbackend" for "firewalld" by adding or editing the following line in "etc/firewalld/firewalld.conf":

FirewallBackend=nftables

Establish rate-limiting rules based on organization-defined types of DoS attacks on impacted network interfaces.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-257939'
  tag rid: 'SV-257939r958902_rule'
  tag stig_id: 'RHEL-09-251030'
  tag fix_id: 'F-61604r925803_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5', 'SC-5 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe parse_config_file('/etc/firewalld/firewalld.conf') do
    its('FirewallBackend') { should eq 'nftables' }
  end
end
