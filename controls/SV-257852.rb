control 'SV-257852' do
  title 'RHEL 9 must prevent code from being executed on file systems that contain user home directories.'
  desc 'The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/home" is mounted with the "noexec" option with the following command:

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is automatically a finding, as the "noexec" option cannot be used on the "/" system.

$ mount | grep /home

tmpfs on /home type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/home" file system is mounted without the "noexec" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "noexec" option on the "/home" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257852'
  tag rid: 'SV-257852r925543_rule'
  tag stig_id: 'RHEL-09-231055'
  tag fix_id: 'F-61517r925542_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  interactive_users = passwd.where {
    uid.to_i >= 1000 && shell !~ /nologin/
  }

  interactive_user_homedirs = interactive_users.homes.map { |home_path|
    home_path.match(%r{^(.*)/.*$}).captures.first
  }.uniq

  option = 'noexec'

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
