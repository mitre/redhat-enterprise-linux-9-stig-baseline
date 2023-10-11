control 'SV-257940' do
  title 'RHEL 9 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary ports, protocols, and services on information systems.'
  desc 'check', 'Inspect the firewall configuration and running services to verify it is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited.

Check which services are currently active with the following command:

$ sudo firewall-cmd --list-all-zones

custom (active)
target: DROP
icmp-block-inversion: no
interfaces: ens33
sources: 
services: dhcpv6-client dns http https ldaps rpc-bind ssh
ports: 
masquerade: no
forward-ports: 
icmp-blocks: 
rich rules: 

Ask the system administrator for the site or program Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA). Verify the services allowed by the firewall match the PPSM CLSA. 

If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding.'
  desc 'fix', "Update the host's firewall settings and/or running services to comply with the PPSM CLSA for the site or program and the PPSM CAL.

Then run the following command to load the newly created rule(s):

$ sudo firewall-cmd --reload"
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61681r925805_chk'
  tag severity: 'medium'
  tag gid: 'V-257940'
  tag rid: 'SV-257940r925807_rule'
  tag stig_id: 'RHEL-09-251035'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-61605r925806_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
