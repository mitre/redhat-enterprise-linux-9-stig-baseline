control 'SV-257855' do
  title 'RHEL 8 must prevent code from being executed on file systems that are
imported via Network File System (NFS).'
  desc 'The "noexec" mount option causes the system not to execute binary
files. This option must be used for mounting any file system not containing
approved binary as they may be incompatible. Executing files from untrusted
file systems increases the opportunity for unprivileged users to attain
unauthorized administrative access.'
  desc 'check', 'Verify that  file systems being imported via NFS are mounted with the
"noexec" option with the following command:

    $ sudo grep nfs /etc/fstab | grep noexec

    UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid,nodev,noexec
0 0

    If a file system found in "/etc/fstab" refers to NFS and it does not have
the "noexec" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "noexec" option on
file systems that are being imported via NFS.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230306'
  tag rid: 'SV-257855r627750_rule'
  tag stig_id: 'RHEL-08-010630'
  tag fix_id: 'F-32950r567665_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  option = 'noexec'
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
