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

  mount_option = 'nodev'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    home_dirs = []
    passwd.where { uid.to_i >= 1000 && shell !~ /nologin/ }.entries.each do |ie|
      username_size = ie.user.length
      home_size = ie.home.length
      home_dirs.append(ie.home[0..home_size - (username_size + 2)])
    end
    home_dirs.uniq.each do |home_dir|
      describe 'User home directories should not be mounted under root' do
        subject { home_dir }
        it { should_not eq '/' }
      end
      describe etc_fstab.where { mount_point == home_dir } do
        it { should be_configured }
        its('mount_options.first') { should include mount_option }
      end
    end
  end
end
