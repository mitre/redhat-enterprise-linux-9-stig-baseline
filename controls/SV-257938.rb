control 'SV-257938' do
  title 'RHEL 9 must control remote access methods.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business.

'
  desc 'check', 'Inspect the list of enabled firewall ports and verify they are configured correctly by running the following command:

$ sudo firewall-cmd --list-all 

Ask the system administrator for the site or program Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA). Verify the services allowed by the firewall match the PPSM CLSA. 

If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), or there are no firewall rules configured, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to allow approved settings and/or running services to comply with the PPSM CLSA for the site or program and the PPSM CAL.

To open a port for a service, configure firewalld using the following command:

$ sudo firewall-cmd --permanent --add-port=port_number/tcp
or
$ sudo firewall-cmd --permanent --add-service=service_name'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61679r925799_chk'
  tag severity: 'medium'
  tag gid: 'V-257938'
  tag rid: 'SV-257938r925801_rule'
  tag stig_id: 'RHEL-09-251025'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-61603r925800_fix'
  tag satisfies: ['SRG-OS-000096-GPOS-00050', 'SRG-OS-000297-GPOS-00115']
  tag 'documentable'
  tag cci: ['CCI-000382', 'CCI-002314']
  tag nist: ['CM-7 b', 'AC-17 (1)']
end
