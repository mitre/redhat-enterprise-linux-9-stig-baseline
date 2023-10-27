control 'SV-257858' do
  title 'RHEL 9 must prevent special devices on file systems that are used with removable media.'
  desc 'The "nodev" mount option causes the system not to interpret character or block special devices. Executing character or blocking special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify file systems that are used for removable media are mounted with the "nodev" option with the following command:

$ more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid,nodev,noexec 0 0

If a file system found in "/etc/fstab" refers to removable media and it does not have the "nodev" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nodev" option on file systems that are associated with removable media.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61599r925559_chk'
  tag severity: 'medium'
  tag gid: 'V-257858'
  tag rid: 'SV-257858r925561_rule'
  tag stig_id: 'RHEL-09-231085'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61523r925560_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  mount_point = 'nodev'
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
