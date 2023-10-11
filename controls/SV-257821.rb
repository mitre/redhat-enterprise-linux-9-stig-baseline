control 'SV-257821' do
  title 'RHEL 9 must check the GPG signature of locally installed software packages before installation.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

All software packages must be signed with a cryptographic key recognized and approved by the organization.

Verifying the authenticity of software prior to installation validates the integrity of the software package received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor.'
  desc 'check', 'Verify that dnf always checks the GPG signature of locally installed software packages before installation:

$ grep localpkg_gpgcheck /etc/dnf/dnf.conf 

localpkg_gpgcheck=1 

If "localpkg_gpgcheck" is not set to "1", or if the option is missing or commented out, ask the system administrator how the GPG signatures of local software packages are being verified.

If there is no process to verify GPG signatures that is approved by the organization, this is a finding.'
  desc 'fix', 'Configure dnf to always check the GPG signature of local software packages before installation.

Add or update the following line in the [main] section of the /etc/dnf/dnf.conf file:

localpkg_gpgcheck=1'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61562r925448_chk'
  tag severity: 'high'
  tag gid: 'V-257821'
  tag rid: 'SV-257821r925450_rule'
  tag stig_id: 'RHEL-09-214020'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-61486r925449_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
