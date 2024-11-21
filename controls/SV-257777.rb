control 'SV-257777' do
  title 'RHEL 9 must be a vendor-supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

Red Hat offers the Extended Update Support (EUS) add-on to a Red Hat Enterprise Linux subscription, for a fee, for those customers who wish to standardize on a specific minor release for an extended period.'
  desc 'check', 'Verify that the version or RHEL 9 is vendor supported with the following command:

$ cat /etc/redhat-release

Red Hat Enterprise Linux release 9.2 (Plow)

If the installed version of RHEL 9 is not supported, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of RHEL 9.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257777'
  tag rid: 'SV-257777r925318_rule'
  tag stig_id: 'RHEL-09-211010'
  tag fix_id: 'F-61442r925317_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  release = os.release

  # Note that versions 9.0 and 9.2 of RHEL9 are within the EUS window at
  # time of writing.

  # 9.1 is not a EUS-supported release and is no longer officially supported
  # by Red Hat. The date given for the expiration for 9.1 is based on the
  # RHEL9 Planning Guide diagram found on Red Hat's Life Cycle page:
  # https://access.redhat.com/support/policy/updates/errata/#Life_Cycle_Dates

  EOMS_DATE = {
    /^9\.0/ => 'May 31, 2024',
    /^9\.1/ => 'April 1, 2023',
    /^9\.2/ => 'May 31, 2025',
    /^9\.3/ => 'April 30, 2024',
    /^9\.4/ => 'May 31, 2026',
    /^9\.5/ => 'April 30, 2025',
    /^9\.6/ => 'May 31, 2027',
    /^9\.7/ => 'April 30, 2026',
    /^9\.8/ => 'May 31, 2028',
    /^9\.9/ => 'April 30, 2027',
    /^9\.10/ => 'May 31, 2032',
  }.find { |k, _v| k.match(release) }&.last

  describe "The release \"#{release}\"" do
    if EOMS_DATE.nil?
      it 'is a supported release' do
        expect(EOMS_DATE).not_to be_nil, "Release '#{release}' has no specified support window"
      end
    else
      it 'is still within the support window' do
        expect(Date.today).to be <= Date.parse(EOMS_DATE)
      end
    end
  end
end
