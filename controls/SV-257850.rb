control 'SV-257850' do
  title 'RHEL 9 must prevent device files from being interpreted on file systems that contain user home directories.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', 'Verify "/home" is mounted with the "nodev" option with the following command:

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is automatically a finding, as the "nodev" option cannot be used on the "/" system.

$ mount | grep /home

tmpfs on /home type tmpfs (rw,nodev,nosuid,noexec,seclabel)

If the "/home" file system is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "nodev" option on the "/home" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61591r925535_chk'
  tag severity: 'medium'
  tag gid: 'V-257850'
  tag rid: 'SV-257850r925537_rule'
  tag stig_id: 'RHEL-09-231045'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61515r925536_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  interactive_users = passwd.where {
    uid.to_i >= 1000 && shell !~ /nologin/
  }

  interactive_user_homedirs = interactive_users.homes.map { |home_path|
    home_path.match(%r{^(.*)/.*$}).captures.first
  }.uniq

  option = 'nosuid'

  mounted_on_root = interactive_user_homedirs.select { |dir| dir == '/' }
  not_configured = interactive_user_homedirs.reject { |dir| etc_fstab.where { mount_point == dir }.configured? }
  option_not_set = interactive_user_homedirs.reject { |dir| etc_fstab.where { mount_point == dir }.mount_options.flatten.include?(option) }

  describe 'All interactive user home directories' do
    it "should not be mounted under root ('/')" do
      expect(mounted_on_root).to be_empty, "Home directories mounted on root ('/'):\n\t- #{mounted_on_root.join("\n\t- ")}"
    end
    it 'should be configured in /etc/fstab' do
      expect(not_configured).to be_empty, "Unconfigured home directories:\n\t- #{not_configured.join("\n\t- ")}"
    end
    if (option_not_set - not_configured).nil?
      it "should have the '#{option}' mount option set" do
        expect(option_not_set - not_configured).to be_empty, "Mounted home directories without '#{option}' set:\n\t- #{not_configured.join("\n\t- ")}"
      end
    end
  end
end
