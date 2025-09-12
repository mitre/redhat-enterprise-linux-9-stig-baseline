control 'SV-257854' do
  title 'RHEL 9 must prevent special devices on file systems that are imported via Network File System (NFS).'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Note: If no NFS mounts are configured, this requirement is Not Applicable.

Verify RHEL 9 has the "nodev" option configured for all NFS mounts with the following command:

$ grep nfs /etc/fstab

192.168.22.2:/mnt/export /data nfs4 rw,nosuid,nodev,noexec,sync,soft,sec=krb5:krb5i:krb5p

If the system is mounting file systems via NFS and the "nodev" option is missing, this is a finding.'
  desc 'fix', 'Update each NFS mounted file system to use the "nodev" option on file systems that are being imported via NFS.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257854'
  tag rid: 'SV-257854r1044934_rule'
  tag stig_id: 'RHEL-09-231065'
  tag fix_id: 'F-61519r925548_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  option = 'nodev'
  nfs_file_systems = etc_fstab.nfs_file_systems.params
  failing_mounts = nfs_file_systems.reject { |mnt| mnt['mount_options'].include?(option) }

  if nfs_file_systems.empty?
    impact 0.0
    describe 'N/A' do
      skip 'No NFS mounts are configured'
    end
  else
    describe 'Any mounted Network File System (NFS)' do
      it "should have '#{option}' set" do
        expect(failing_mounts).to be_empty, "NFS without '#{option}' set:\n\t- #{failing_mounts.join("\n\t- ")}"
      end
    end
  end
end
