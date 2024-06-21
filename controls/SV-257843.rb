control 'SV-257843' do
  title 'A separate RHEL 9 file system must be used for user home directories (such as /home or an equivalent).'
  desc 'Ensuring that "/home" is mounted on its own partition enables the setting of more restrictive mount options, and also helps ensure that users cannot trivially fill partitions used for log or audit data storage.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/home" with the following command:

$ mount | grep /home

UUID=fba5000f-2ffa-4417-90eb-8c54ae74a32f on /home type ext4 (rw,nodev,nosuid,noexec,seclabel)

If a separate entry for "/home" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/home" directory onto a separate file system/partition.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257843'
  tag rid: 'SV-257843r925516_rule'
  tag stig_id: 'RHEL-09-231010'
  tag fix_id: 'F-61508r925515_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable inside a container; the host manages the container filesystem') {
    !virtualization.system.eql?('docker')
  }

  ignore_shells = input('non_interactive_shells').join('|')
  homes = users.where { uid >= 1000 && !shell.match(ignore_shells) }.homes
  root_device = etc_fstab.where { mount_point == '/' }.device_name

  if input('exempt_separate_filesystem')
    impact 0.0
    describe 'This system is not required to have separate filesystems for each mount point' do
      skip 'The system is managing filesystems and space via other mechanisms; this requirement is Not Applicable'
    end
  else
    homes.each do |home|
      pn_parent = Pathname.new(home).parent.to_s
      home_device = etc_fstab.where { mount_point == pn_parent }.device_name

      describe "The '#{pn_parent}' mount point" do
        subject { home_device }

        it 'is not on the same partition as the root partition' do
          is_expected.not_to equal(root_device)
        end

        it 'has its own partition' do
          is_expected.not_to be_empty
        end
      end
    end
  end
end
