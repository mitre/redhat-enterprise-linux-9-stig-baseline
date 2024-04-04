control 'SV-257851' do
  title 'RHEL 8 must prevent files with the setuid and setgid bit set from
being executed on file systems that contain user home directories.'
  desc 'The "nosuid" mount option causes the system not to execute
"setuid" and "setgid" files with owner privileges. This option must be used
for mounting any file system not containing approved "setuid" and "setguid"
files. Executing files from untrusted file systems increases the opportunity
for unprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(Verify file systems that contain user home directories are mounted with the
"nosuid" option.

    Note: If a separate file system has not been created for the user home
directories (user home directories are mounted under "/"), this is
automatically a finding as the "nosuid" option cannot be used on the "/"
system.

    Find the file system(s) that contain the user home directories with the
following command:

    $ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd

    smithj:1001: /home/smithj
    robinst:1002: /home/robinst

    Check the file systems that are mounted at boot time with the following
command:

    $ sudo more /etc/fstab

    UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home xfs
rw,relatime,discard,data=ordered,nosuid,nodev,noexec 0 0

    If a file system found in "/etc/fstab" refers to the user home directory
file system and it does not have the "nosuid" option set, this is a finding.)
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on
file systems that contain user home directories for interactive users.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230299'
  tag rid: 'SV-257851r627750_rule'
  tag stig_id: 'RHEL-08-010570'
  tag fix_id: 'F-32943r567644_fix'
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
