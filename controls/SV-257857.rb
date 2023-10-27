control 'SV-257857' do
  title 'RHEL 9 must prevent code from being executed on file systems that are used with removable media.'
  desc 'The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify file systems that are used for removable media are mounted with the "noexec" option with the following command:

$ more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid,nodev,noexec 0 0

If a file system found in "/etc/fstab" refers to removable media and it does not have the "noexec" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "noexec" option on file systems that are associated with removable media.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61598r925556_chk'
  tag severity: 'medium'
  tag gid: 'V-257857'
  tag rid: 'SV-257857r925558_rule'
  tag stig_id: 'RHEL-09-231080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61522r925557_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  mount_point = 'noexec'
  non_removable_media_fs = input('non_removable_media_fs')

  file_systems = etc_fstab.params
  if !file_systems.nil? && !file_systems.empty?
    file_systems.each do |file_sys_line|
      if !non_removable_media_fs.include?(file_sys_line['mount_point'])
        describe "The mount point #{file_sys_line['mount_point']}" do
          subject { file_sys_line['mount_options'] }
          it { should include mount_point }
        end
      else
        describe "File system \"#{file_sys_line['mount_point']}\" does not correspond to removable media." do
          subject { non_removable_media_fs.include?(file_sys_line['mount_point']) }
          it { should eq true }
        end
      end
    end
  else
    describe 'No file systems were found.' do
      subject { file_systems.nil? }
      it { should eq true }
    end
  end
end
