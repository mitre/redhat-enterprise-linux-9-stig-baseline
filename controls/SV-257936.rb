control 'SV-257936' do
  title 'The firewalld service on RHEL 9 must be active.'
  desc '"Firewalld" provides an easy and effective way to block/limit remote access to the system via ports, services, and protocols.

Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

RHEL 9 functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

'
  desc 'check', 'Verify that "firewalld" is active with the following command:

$ systemctl is-active firewalld 

active

If the firewalld service is not active, this is a finding.'
  desc 'fix', 'To enable the firewalld service run the following command:

$ sudo systemctl enable --now firewalld'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61677r925793_chk'
  tag severity: 'medium'
  tag gid: 'V-257936'
  tag rid: 'SV-257936r925795_rule'
  tag stig_id: 'RHEL-09-251015'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-61601r925794_fix'
  tag satisfies: ['SRG-OS-000096-GPOS-00050', 'SRG-OS-000297-GPOS-00115', 'SRG-OS-000480-GPOS-00227', 'SRG-OS-000480-GPOS-00232']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000382', 'CCI-002314']
  tag nist: ['CM-6 b', 'CM-7 b', 'AC-17 (1)']
end
