control 'SV-257854' do
  title 'RHEL 9 must prevent special devices on file systems that are imported via Network File System (NFS).'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify RHEL 9 has the "nodev" option configured for all NFS mounts with the following command:

$ cat /etc/fstab | grep nfs

192.168.22.2:/mnt/export /data nfs4 rw,nosuid,nodev,noexec,sync,soft,sec=krb5:krb5i:krb5p

Note: If no NFS mounts are configured, this requirement is Not Applicable.

If the system is mounting file systems via NFS and the "nodev" option is missing, this is a finding.'
  desc 'fix', 'Update each NFS mounted file system to use the "nodev" option on file systems that are being imported via NFS.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61595r925547_chk'
  tag severity: 'medium'
  tag gid: 'V-257854'
  tag rid: 'SV-257854r925549_rule'
  tag stig_id: 'RHEL-09-231065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61519r925548_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  mount_point = 'dev'
  nfs_systems = etc_fstab.nfs_file_systems.entries

  if !nfs_systems.nil? && !nfs_systems.empty?
    nfs_systems.each do |nfs_system|
      describe "Network File System mounted on #{nfs_system['mount_point']}" do
        subject { nfs_system }
        its('mount_options') { should include mount_point }
      end
    end
  else
    describe 'No NFS file systems were found' do
      subject { nfs_systems.nil? || nfs_systems.empty? }
      it { should eq true }
    end
  end
end
