control 'SV-257941' do
  title 'RHEL 9 network interfaces must not be in promiscuous mode.'
  desc 'Network interfaces in promiscuous mode allow for the capture of all network traffic visible to the system. If unauthorized individuals can access these applications, it may allow them to collect information such as logon IDs, passwords, and key exchanges between systems.

If the system is being used to perform a network troubleshooting function, the use of these tools must be documented with the information systems security officer (ISSO) and restricted to only authorized personnel.'
  desc 'check', 'Verify network interfaces are not in promiscuous mode with the following command:

$ ip link | grep -i promisc

If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding.'
  desc 'fix', 'Configure network interfaces to turn off promiscuous mode unless approved by the ISSO and documented.

Set the promiscuous mode of an interface to off with the following command:

$ sudo ip link set dev <devicename> multicast off promisc off'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61682r925808_chk'
  tag severity: 'medium'
  tag gid: 'V-257941'
  tag rid: 'SV-257941r925810_rule'
  tag stig_id: 'RHEL-09-251040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61606r925809_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
