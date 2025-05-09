control 'SV-257949' do
  title 'RHEL 9 must configure a DNS processing mode in Network Manager.'
  desc 'In order to ensure that DNS resolver settings are respected, a DNS mode in Network Manager must be configured.'
  desc 'check', 'Verify that RHEL 9 has a DNS mode configured in Network Manager.

$ NetworkManager --print-config
[main]
dns=none

If the dns key under main does not exist or is not set to "none" or "default", this is a finding.

Note: If RHEL 9 is configured to use a DNS resolver other than Network Manager, the configuration must be documented and approved by the information system security officer (ISSO).'
  desc 'fix', 'Configure NetworkManager in RHEL 9 to use a DNS mode.

In "/etc/NetworkManager/NetworkManager.conf" add the following line in the "[main]" section:

dns = none

NetworkManager must be reloaded for the change to take effect.

$ sudo systemctl reload NetworkManager'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61690r1014840_chk'
  tag severity: 'medium'
  tag gid: 'V-257949'
  tag rid: 'SV-257949r1014841_rule'
  tag stig_id: 'RHEL-09-252040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61614r925833_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  network_manager = command('NetworkManager --print-config')

  if network_manager.stdout == '' && !network_manager.stderr.empty?
    describe 'NetworkManager' do
      it 'should be installed' do
        expect(network_manager.stdout).not_to be_empty, 'NetworkManager not found on system'
      end
    end
  else
    describe ini(network_manager) do
      its('main.dns') { should exist }
      its('main.dns') { should be_in ['none', 'default'] }
    end
  end
end
