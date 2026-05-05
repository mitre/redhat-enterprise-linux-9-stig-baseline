control 'SV-257937' do
  title 'The RHEL 9 firewall must employ a deny-all, allow-by-exception policy for allowing connections to other systems.'
  desc 'Failure to restrict network connectivity only to authorized systems permits inbound connections from malicious systems. It also permits outbound connections that may facilitate exfiltration of DOD data.

RHEL 9 incorporates the "firewalld" daemon, which allows for many different configurations. One of these configurations is zones. Zones can be utilized to a deny-all, allow-by-exception approach. The default "drop" zone will drop all incoming network packets unless it is explicitly allowed by the configuration file or is related to an outgoing network connection.'
  desc 'check', 'Verify the RHEL 9 firewalld is configured to employ a deny-all, allow-by-exception policy for allowing connections to other systems with the following commands:

Ensure firewalld is running:
$ sudo firewall-cmd --state
running

Identify active zones:
$ sudo firewall-cmd --get-active-zones
drop
  interfaces: ens192

Check what rules are applied in that zone:
$ sudo firewall-cmd --list-all --zone=$(firewall-cmd --get-default-zone)
drop (active)
  target: DROP
  icmp-block-inversion: no
  interfaces: ens192
  sources:
  services: ssh
  ports:
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:

If no zones are active on the RHEL 9 interfaces or if runtime and permanent targets are set to a different option other than "DROP", this is a finding.'
  desc 'fix', 'Configure the "firewalld" daemon to employ a deny-all, allow-by-exception policy with the following commands:

Start by adding the exceptions that are required for mission functionality to the "drop" zone. If SSH access on port 22 is needed, for example, run the following: "sudo firewall-cmd --permanent --add-service=ssh --zone=drop"

Reload the firewall rules to update the runtime configuration from the "--permanent" changes made above:
$ sudo firewall-cmd --reload

Set the default zone to the drop zone:
$ sudo firewall-cmd --set-default-zone=drop
Note: This is a runtime and permanent change.

Add any interfaces to the newly modified "drop" zone:
$ sudo firewall-cmd --permanent --zone=drop --change-interface=ens192

Reload the firewall rules for changes to take effect:
$ sudo firewall-cmd --reload'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155', 'SRG-OS-000480-GPOS-00232']
  tag gid: 'V-257937'
  tag rid: 'SV-257937r1106310_rule'
  tag stig_id: 'RHEL-09-251020'
  tag fix_id: 'F-61602r1102092_fix'
  tag cci: ['CCI-001764', 'CCI-000366']
  tag nist: ['CM-7 (2)', 'CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe service('firewalld') do
    it { should be_running }
  end

  describe firewalld do
    its('zone') { should_not be_empty }
  end

  failing_zones = firewalld.zone.select { |fz| firewalld.zone(fz).target == 'DROP' }

  describe 'All firewall zones' do
    it 'should be configured to drop all incoming network packets unless explicitly accepted' do
      expect(failing_zones).to be_empty, "Failing zones:\n\t- #{failing_zones.join("\n\t- ")}"
    end
  end
end
