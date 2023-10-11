control 'SV-257950' do
  title 'RHEL 9 must not have unauthorized IP tunnels configured.'
  desc 'IP tunneling mechanisms can be used to bypass network filtering. If tunneling is required, it must be documented with the information system security officer (ISSO).'
  desc 'check', 'Verify that RHEL 9 does not have unauthorized IP tunnels configured.

Determine if the "IPsec" service is active with the following command:

$ systemctl status ipsec

ipsec.service - Internet Key Exchange (IKE) Protocol Daemon for IPsec
Loaded: loaded (/usr/lib/systemd/system/ipsec.service; disabled)
Active: inactive (dead)

If the "IPsec" service is active, check for configured IPsec connections ("conn"), with the following command:

$ grep -rni conn /etc/ipsec.conf /etc/ipsec.d/ 

Verify any returned results are documented with the ISSO.

If the IPsec tunnels are active and not approved, this is a finding.'
  desc 'fix', 'Remove all unapproved tunnels from the system, or document them with the ISSO.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61691r925835_chk'
  tag severity: 'medium'
  tag gid: 'V-257950'
  tag rid: 'SV-257950r925837_rule'
  tag stig_id: 'RHEL-09-252045'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61615r925836_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
