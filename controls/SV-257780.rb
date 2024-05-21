control 'SV-257780' do
  title 'RHEL 9 must implement the Endpoint Security for Linux Threat Prevention tool.'
  desc 'Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the operating system may have an integrated solution incorporating continuous scanning using ESS and periodic scanning using other tools, as specified in the requirement.'
  desc 'check', 'Verify that RHEL 9 has implemented the Endpoint Security for Linux Threat Prevention tool.

Check that the following package has been installed:

$ sudo rpm -qa | grep -i mcafeetp

If the "mcafeetp" package is not installed, this is a finding.

Verify that the daemon is running:

$ sudo ps -ef | grep -i mfetpd

If the daemon is not running, this is a finding.'
  desc 'fix', 'Install and enable the latest McAfee ENSLTP package.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag gid: 'V-257780'
  tag rid: 'SV-257780r939261_rule'
  tag stig_id: 'RHEL-09-211025'
  tag fix_id: 'F-61445r925326_fix'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  if input('skip_endpoint_security_tool')
    impact 0.0
    describe 'Implementing the Endpoint Security for Linux Threat Prevention tool is not applicable by agreement with  the approval authority of the organization.' do
      skip 'Implementing the Endpoint Security for Linux Threat Prevention tool is not applicable by agreement with  the approval authority of the organization.'
    end
  else
    linux_threat_prevention_package = input('linux_threat_prevention_package')
    linux_threat_prevention_service = input('linux_threat_prevention_service')
    describe package(linux_threat_prevention_package) do
      it { should be_installed }
    end

    describe processes(linux_threat_prevention_service) do
      it { should exist }
    end
  end
end
