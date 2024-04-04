control 'SV-257777' do
  title 'RHEL 8 must be a vendor-supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

  Red Hat offers the Extended Update Support (EUS) add-on to a Red Hat Enterprise Linux subscription, for a fee, for those customers who wish to standardize on a specific minor release for an extended period. The RHEL 8 minor releases eligible for EUS are 8.1, 8.2, 8.4, 8.6, and 8.8. Each RHEL 8 EUS stream is available for 24 months from the availability of the minor release. RHEL 8.10 will be the final minor release overall. For more details on the Red Hat Enterprise Linux Life Cycle  visit https://access.redhat.com/support/policy/updates/errata/.

  Note: The life-cycle time spans and dates are subject to adjustment.'
  desc 'check', 'Verify the version of the operating system is vendor supported.

Note: The lifecycle time spans and dates are subject to adjustment.

Check the version of the operating system with the following command:

$ sudo cat /etc/redhat-release

Red Hat Enterprise Linux Server release 8.6 (Ootpa)

Current End of Extended Update Support for RHEL 8.1 is 30 November 2021.

Current End of Extended Update Support for RHEL 8.2 is 30 April 2022.

Current End of Extended Update Support for RHEL 8.4 is 31 May 2023.

Current End of Maintenance Support for RHEL 8.5 is 31 May 2022.

Current End of Extended Update Support for RHEL 8.6 is 31 May 2024.

Current End of Maintenance Support for RHEL 8.7 is 31 May 2023.

Current End of Extended Update Support for RHEL 8.8 is 31 May 2025.

Current End of Maintenance Support for RHEL 8.9 is 31 May 2024.

Current End of Maintenance Support for RHEL 8.10 is 31 May 2029.

If the release is not supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of RHEL 8.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230221'
  tag rid: 'SV-257777r858734_rule'
  tag stig_id: 'RHEL-08-010000'
  tag fix_id: 'F-32865r567410_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  release = os.release

  EOMS_DATE = {
    /^8\.1/ => '30 November 2021',
    /^8\.2/ => '30 April 2022',
    /^8\.3/ => '30 April 2021',
    /^8\.4/ => '31 May 2023',
    /^8\.5/ => '31 May 2022',
    /^8\.6/ => '31 May 2024',
    /^8\.7/ => '31 May 2023',
    /^8\.8/ => '31 May 2025',
    /^8\.9/ => '31 May 2024',
    /^8\.10/ => '31 May 2029'
  }.find { |k, _v| k.match(release) }&.last

  describe "The release \"#{release}\" is still be within the support window" do
    it "ending on #{EOMS_DATE}" do
      expect(Date.today).to be <= Date.parse(EOMS_DATE)
    end
  end
end
