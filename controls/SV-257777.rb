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
  tag check_id: 'C-61518r925316_chk'
  tag severity: 'high'
  tag gid: 'V-257777'
  tag rid: 'SV-257777r925318_rule'
  tag stig_id: 'RHEL-09-211010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61442r925317_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
