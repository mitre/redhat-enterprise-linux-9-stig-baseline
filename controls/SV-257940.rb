control 'SV-257940' do
  title 'RHEL 8 must be configured to prohibit or restrict the use of
functions, ports, protocols, and/or services, as defined in the Ports,
Protocols, and Services Management (PPSM) Category Assignments List (CAL) and
vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer
of information, or unauthorized tunneling (i.e., embedding of data types within
data types), organizations must disable or restrict unused or unnecessary
physical and logical ports/protocols on information systems.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services provided by default may not be
necessary to support essential organizational operations. Additionally, it is
sometimes convenient to provide multiple services from a single component
(e.g., VPN and IPS); however, doing so increases risk over limiting the
services provided by any one component.

    To support the requirements and principles of least functionality, the
operating system must support the organizational requirements, providing only
essential capabilities and limiting the use of ports, protocols, and/or
services to only those required, authorized, and approved to conduct official
business or to address authorized quality-of-life issues.'
  desc 'check', 'Inspect the firewall configuration and running services to verify it is
configured to prohibit or restrict the use of functions, ports, protocols,
and/or services that are unnecessary or prohibited.

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

    Ask the System Administrator for the site or program Ports, Protocols, and
Services Management Component Local Service Assessment (PPSM CLSA). Verify the
services allowed by the firewall match the PPSM CLSA.

    If there are additional ports, protocols, or services that are not in the
PPSM CLSA, or there are ports, protocols, or services that are prohibited by
the PPSM Category Assurance List (CAL), this is a finding.'
  desc 'fix', "Update the host's firewall settings and/or running services to
comply with the PPSM Component Local Service Assessment (CLSA) for the site or
program and the PPSM CAL."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-230500'
  tag rid: 'SV-257940r627750_rule'
  tag stig_id: 'RHEL-08-040030'
  tag fix_id: 'F-33144r568247_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  firewalld_properties = input('firewalld_properties')

  describe firewalld do
    it { should be_running }
  end
  describe firewalld do
    its('ports') { should cmp [firewalld_properties['ports']] }
    its('protocols') { should cmp [firewalld_properties['protocols']] }
    its('services') { should cmp [firewalld_properties['services']] }
  end
end
