control 'SV-257937' do
  title 'A RHEL 9 firewall must employ a deny-all, allow-by-exception policy for allowing connections to other systems.'
  desc 'Failure to restrict network connectivity only to authorized systems permits inbound connections from malicious systems. It also permits outbound connections that may facilitate exfiltration of DOD data.

RHEL 9 incorporates the "firewalld" daemon, which allows for many different configurations. One of these configurations is zones. Zones can be utilized to a deny-all, allow-by-exception approach. The default "drop" zone will drop all incoming network packets unless it is explicitly allowed by the configuration file or is related to an outgoing network connection.'
  desc 'check', 'Verify the RHEL 9 "firewalld" is configured to employ a deny-all, allow-by-exception policy for allowing connections to other systems with the following commands:

$ sudo  firewall-cmd --state

running

$ sudo firewall-cmd --get-active-zones

public
   interfaces: ens33

$ sudo firewall-cmd --info-zone=public | grep target

   target: DROP

$ sudo firewall-cmd --permanent --info-zone=public | grep target

   target: DROP

If no zones are active on the RHEL 9 interfaces or if runtime and permanent targets are set to a different option other than "DROP", this is a finding.'
  desc 'fix', 'Configure the "firewalld" daemon to employ a deny-all, allow-by-exception with the following commands:

Start by adding the exceptions that are required for mission functionality to the "drop" zone. If SSH access on port 22 is needed, for example, run the following: "sudo firewall-cmd --permanent --add-service=ssh --zone=drop"

Reload the firewall rules to update the runtime configuration from the "--permanent" changes made above:
$ sudo firewall-cmd --reload

Set the default zone to the drop zone:
$ sudo firewall-cmd --set-default-zone=drop
Note: This is a runtime and permanent change.

Add any interfaces to the newly modified "drop" zone:
$ sudo firewall-cmd --permanent --zone=drop --change-interface=ens33

Reload the firewall rules for changes to take effect:
$ sudo firewall-cmd --reload'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155', 'SRG-OS-000480-GPOS-00232']
  tag gid: 'V-257937'
  tag rid: 'SV-257937r925798_rule'
  tag stig_id: 'RHEL-09-251020'
  tag fix_id: 'F-61602r925797_fix'
  tag cci: ['CCI-001764', 'CCI-000366']
  tag nist: ['CM-7 (2)', 'CM-6 b']

  #TODO?

  # Check if the system is a Docker container or not using Fapolicyd
  if virtualization.system.eql?('docker') || !input('use_fapolicyd')
    impact 0.0
    describe 'Control not applicable' do
      skip 'The organization is not using the Fapolicyd service to manage firewall services, this control is Not Applicable' unless input('use_fapolicyd')
      skip 'Control not applicable within a container' if virtualization.system.eql?('docker')
    end
  else
    # Parse the fapolicyd configuration file
    fapolicyd_config = parse_config_file('/etc/fapolicyd/fapolicyd.conf')

    describe 'Fapolicyd configuration' do
      it 'permissive should not be commented out' do
        expect(fapolicyd_config.content).to match(/^permissive\s*=\s*0$/), 'permissive is commented out in the fapolicyd.conf file'
      end
      it 'should have permissive set to 0' do
        expect(fapolicyd_config.params['permissive']).to cmp '0'
      end
    end

    # Determine the rules file based on the OS release
    rules_file = os.release.to_f < 8.4 ? '/etc/fapolicyd/fapolicyd.rules' : '/etc/fapolicyd/compiled.rules'

    # Check if the rules file exists
    describe file(rules_file) do
      it { should exist }
    end

    # If the rules file exists, check the last rule
    if file(rules_file).exist?
      rules = file(rules_file).content.strip.split("\n")
      last_rule = rules.last

      describe 'Last rule in the rules file' do
        it { expect(last_rule).to cmp 'deny perm=any all : all' }
      end
    end
  end
end
