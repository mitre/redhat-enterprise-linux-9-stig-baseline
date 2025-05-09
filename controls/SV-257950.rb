control 'SV-257950' do
  title 'RHEL 9 must not have unauthorized IP tunnels configured.'
  desc 'IP tunneling mechanisms can be used to bypass network filtering. If tunneling is required, it must be documented with the information system security officer (ISSO).'
  desc 'check', 'Verify that RHEL 9 does not have unauthorized IP tunnels configured.

Determine if the "IPsec" service is active with the following command:

$ systemctl is-active ipsec

Inactive

If the "IPsec" service is active, check for configured IPsec connections ("conn"), with the following command:

$ sudo grep -rni conn /etc/ipsec.conf /etc/ipsec.d/ 

Verify any returned results are documented with the ISSO.

If the IPsec tunnels are active and not approved, this is a finding.'
  desc 'fix', 'Remove all unapproved tunnels from the system, or document them with the ISSO.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61691r1045005_chk'
  tag severity: 'medium'
  tag gid: 'V-257950'
  tag rid: 'SV-257950r1045006_rule'
  tag stig_id: 'RHEL-09-252045'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61615r925836_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  describe service('ipsec') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
