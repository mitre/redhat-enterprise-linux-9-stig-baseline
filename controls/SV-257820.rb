control 'SV-257820' do
  title 'RHEL 9 must check the GPG signature of software packages originating from external software repositories before installation.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

All software packages must be signed with a cryptographic key recognized and approved by the organization.

Verifying the authenticity of software prior to installation validates the integrity of the software package received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor.'
  desc 'check', 'Verify that dnf always checks the GPG signature of software packages originating from external software repositories before installation:

$ grep gpgcheck /etc/dnf/dnf.conf

gpgcheck=1

If "gpgcheck" is not set to "1", or if the option is missing or commented out, ask the system administrator how the GPG signatures of software packages are being verified.

If there is no process to verify GPG signatures that is approved by the organization, this is a finding.'
  desc 'fix', 'Configure dnf to always check the GPG signature of software packages originating from external software repositories before installation.

Add or update the following line in the [main] section of the /etc/dnf/dnf.conf file:

gpgcheck=1'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61561r925445_chk'
  tag severity: 'high'
  tag gid: 'V-257820'
  tag rid: 'SV-257820r925447_rule'
  tag stig_id: 'RHEL-09-214015'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-61485r925446_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
