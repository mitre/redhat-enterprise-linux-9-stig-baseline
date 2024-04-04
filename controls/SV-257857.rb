control 'SV-257857' do
  title 'RHEL 8 must prevent code from being executed on file systems that are
used with removable media.'
  desc 'The "noexec" mount option causes the system not to execute binary
files. This option must be used for mounting any file system not containing
approved binary files, as they may be incompatible. Executing files from
untrusted file systems increases the opportunity for unprivileged users to
attain unauthorized administrative access.'
  desc 'check', 'Verify file systems that are used for removable media are mounted with the
"noexec" option with the following command:

    $ sudo more /etc/fstab

    UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat
noauto,owner,ro,nosuid,nodev,noexec 0 0

    If a file system found in "/etc/fstab" refers to removable media and it
does not have the "noexec" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "noexec" option on
file systems that are associated with removable media.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230304'
  tag rid: 'SV-257857r627750_rule'
  tag stig_id: 'RHEL-08-010610'
  tag fix_id: 'F-32948r567659_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  option = 'noexec'
  file_systems = etc_fstab.params
  non_removable_media = input('non_removable_media_fs')
  mounted_removeable_media = file_systems.reject { |mnt| non_removable_media.include?(mnt['mount_point']) }
  failing_mounts = mounted_removeable_media.reject { |mnt| mnt['mount_options'].include?(option) }

  # be very explicit about why this one was a finding since we do not know which mounts are removeable media without the user telling us
  rem_media_msg = "NOTE: Some mounted devices are not indicated to be non-removable media (you may need to update the 'non_removable_media_fs' input to check if these are truly subject to this requirement)\n"

  # there should either be no mounted removable media (which should be a requirement anyway), OR
  # all removeable media should be mounted with noexec
  if mounted_removeable_media.empty?
    describe 'No removeable media' do
      it 'are mounted' do
        expect(mounted_removeable_media).to be_empty
      end
    end
  else
    describe 'Any mounted removeable media' do
      it "should have '#{option}' set" do
        expect(failing_mounts).to be_empty, "#{rem_media_msg}\nRemoveable media without '#{option}' set:\n\t- #{failing_mounts.join("\n\t- ")}"
      end
    end
  end
end
