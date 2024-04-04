control 'SV-257854' do
  title 'RHEL 8 must prevent special devices on file systems that are imported
via Network File System (NFS).'
  desc 'The "nodev" mount option causes the system to not interpret
character or block special devices. Executing character or block special
devices from untrusted file systems increases the opportunity for unprivileged
users to attain unauthorized administrative access.'
  desc 'check', 'Verify file systems that are being NFS-imported are mounted with the
"nodev" option with the following command:

    $ sudo grep nfs /etc/fstab | grep nodev

    UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid,nodev,noexec
0 0

    If a file system found in "/etc/fstab" refers to NFS and it does not have
the "nodev" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nodev" option on
file systems that are being imported via NFS.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230307'
  tag rid: 'SV-257854r627750_rule'
  tag stig_id: 'RHEL-08-010640'
  tag fix_id: 'F-32951r567668_fix'
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
    describe 'No NFS' do
      it 'is mounted' do
        expect(nfs_file_systems).to be_empty
      end
    end
  else
    describe 'Any mounted Network File System (NFS)' do
      it "should have '#{option}' set" do
        expect(failing_mounts).to be_empty, "NFS without '#{option}' set:\n\t- #{failing_mounts.join("\n\t- ")}"
      end
    end
  end
end
