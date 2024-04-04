control 'SV-257936' do
  title 'The firewalld service on RHEL 9 must be active.'
  desc '"Firewalld" provides an easy and effective way to block/limit remote access to the system via ports, services, and protocols.

Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

RHEL 9 functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify that "firewalld" is active with the following command:

$ systemctl is-active firewalld 

active

If the firewalld service is not active, this is a finding.'
  desc 'fix', 'To enable the firewalld service run the following command:

$ sudo systemctl enable --now firewalld'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-257936'
  tag rid: 'SV-257936r925795_rule'
  tag stig_id: 'RHEL-09-251015'
  tag fix_id: 'F-61601r925794_fix'
  tag cci: ['CCI-002314', 'CCI-000366', 'CCI-000382']
  tag nist: ['AC-17 (1)', 'CM-6 b', 'CM-7 b']

  only_if('This requirment is Not Applicable in the container, the container management platform manages the firewall service', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('external_firewall')
    message = 'This system uses an externally managed firewall service, verify with the system administrator that the firewall is configured to requirements'
    describe message do
      skip message
    end
  else
    describe package('firewalld') do
      it { should be_installed }
    end
    describe firewalld do
      it { should be_installed }
      it { should be_running }
    end
  end
end
