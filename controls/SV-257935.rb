control 'SV-257935' do
  title 'RHEL 9 must have the firewalld package installed.'
  desc '"Firewalld" provides an easy and effective way to block/limit remote access to the system via ports, services, and protocols.

Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

RHEL 9 functionality (e.g., SSH) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Run the following command to determine if the firewalld package is installed with the following command:

$ sudo dnf list --installed firewalld 

Example output:

firewalld.noarch          1.0.0-4.el9

If the "firewall" package is not installed, this is a finding.'
  desc 'fix', 'To install the "firewalld" package run the following command:

$ sudo dnf install firewalld'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-257935'
  tag rid: 'SV-257935r928954_rule'
  tag stig_id: 'RHEL-09-251010'
  tag fix_id: 'F-61600r925791_fix'
  tag cci: ['CCI-002314', 'CCI-000366', 'CCI-000382', 'CCI-002322']
  tag nist: ['AC-17 (1)', 'CM-6 b', 'CM-7 b', 'AC-17 (9)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  alternate_firewall_tool = input('alternate_firewall_tool')

  if alternate_firewall_tool != ''
    describe package(alternate_firewall_tool) do
      it { should be_installed }
    end
  else
    describe package('firewalld') do
      it { should be_installed }
    end
  end
end
