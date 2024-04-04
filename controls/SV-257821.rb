control 'SV-257821' do
  title 'RHEL 8 must prevent the installation of software, patches, service
packs, device drivers, or operating system components of local packages without
verification they have been digitally signed using a certificate that is issued
by a Certificate Authority (CA) that is recognized and approved by the
organization.'
  desc 'Changes to any software components can have significant effects on the
overall security of the operating system. This requirement ensures the software
has not been tampered with and that it has been provided by a trusted vendor.

    Accordingly, patches, service packs, device drivers, or operating system
components must be signed with a certificate recognized and approved by the
organization.

    Verifying the authenticity of the software prior to installation validates
the integrity of the patch or upgrade received from a vendor. This verifies the
software has not been tampered with and that it has been provided by a trusted
vendor. Self-signed certificates are disallowed by this requirement. The
operating system should not have to verify the software again. This requirement
does not mandate DoD certificates for this purpose; however, the certificate
used to verify the software must be from an approved CA.'
  desc 'check', 'Verify the operating system prevents the installation of patches, service
packs, device drivers, or operating system components from a repository without
verification that they have been digitally signed using a certificate that is
recognized and approved by the organization.

    Check if YUM is configured to perform a signature check on local packages
with the following command:

    $ sudo grep -i localpkg_gpgcheck /etc/dnf/dnf.conf

    localpkg_gpgcheck =True

    If "localpkg_gpgcheck" is not set to either "1", "True", or "yes",
commented out, or is missing from "/etc/dnf/dnf.conf", this is a finding.'
  desc 'fix', 'Configure the operating system to remove all software components after
updated versions have been installed.

    Set the "localpkg_gpgcheck" option to "True" in the
"/etc/dnf/dnf.conf" file:

    localpkg_gpgcheck=True'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag gid: 'V-230265'
  tag rid: 'SV-257821r877463_rule'
  tag stig_id: 'RHEL-08-010371'
  tag fix_id: 'F-32909r567542_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/dnf/dnf.conf') do
    its('main.localpkg_gpgcheck') { should match(/True|1|yes/i) }
  end
end
