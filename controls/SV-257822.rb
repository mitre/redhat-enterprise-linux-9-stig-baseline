control 'SV-257822' do
  title 'RHEL 9 must have GPG signature verification enabled for all software repositories.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

All software packages must be signed with a cryptographic key recognized and approved by the organization.

Verifying the authenticity of software prior to installation validates the integrity of the software package received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor.'
  desc 'check', 'Verify that all software repositories defined in "/etc/yum.repos.d/" have been configured with "gpgcheck" enabled:

$ grep gpgcheck /etc/yum.repos.d/*.repo | more

gpgcheck = 1

If "gpgcheck" is not set to "1" for all returned lines, this is a finding.'
  desc 'fix', %q(Configure all software repositories defined in "/etc/yum.repos.d/" to have "gpgcheck" enabled:

$ sudo sed -i 's/gpgcheck\s*=.*/gpgcheck=1/g' /etc/yum.repos.d/*)
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61563r925451_chk'
  tag severity: 'high'
  tag gid: 'V-257822'
  tag rid: 'SV-257822r925453_rule'
  tag stig_id: 'RHEL-09-214025'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-61487r925452_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
