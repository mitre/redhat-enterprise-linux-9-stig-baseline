control 'SV-257836' do
  title 'RHEL 9 must not have the quagga package installed.'
  desc 'Quagga is a network routing software suite providing implementations of Open Shortest Path First (OSPF), Routing Information Protocol (RIP), Border Gateway Protocol (BGP) for Unix and Linux platforms.

If there is no need to make the router software available, removing it provides a safeguard against its activation.'
  desc 'check', 'Verify that the quagga package is not installed with the following command:

$ sudo dnf list --installed quagga

Error: No matching Packages to list

If the "quagga" package is installed, and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Remove the quagga package with the following command:

$ sudo dnf remove quagga'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61577r925493_chk'
  tag severity: 'medium'
  tag gid: 'V-257836'
  tag rid: 'SV-257836r925495_rule'
  tag stig_id: 'RHEL-09-215065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61501r925494_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
