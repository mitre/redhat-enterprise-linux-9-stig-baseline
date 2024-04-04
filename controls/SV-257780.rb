control 'SV-257780' do
  title 'The RHEL 8 operating system must implement the Endpoint Security for
Linux Threat Prevention tool.'
  desc "Adding endpoint security tools can provide the capability to
automatically take actions in response to malicious behavior, which can provide
additional agility in reacting to network threats. These tools also often
include a reporting capability to provide network awareness of the system,
which may not otherwise exist in an organization's systems management regime."
  desc 'check', 'Check that the following package has been installed:

     $ sudo rpm -qa | grep -i mcafeetp

If the "mcafeetp" package is not installed, this is a finding.

Verify that the daemon is running:

     $ sudo ps -ef | grep -i mfetpd

If the daemon is not running, this is a finding.'
  desc 'fix', 'Install and enable the latest Trellix ENSLTP package.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag gid: 'V-245540'
  tag rid: 'SV-257780r942951_rule'
  tag stig_id: 'RHEL-08-010001'
  tag fix_id: 'F-48770r942950_fix'
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
