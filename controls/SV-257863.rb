control 'SV-257863' do
  title 'RHEL 9 must mount /dev/shm with the nodev option.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', 'Verify "/dev/shm" is mounted with the "nodev" option with the following command:

$ findmnt /dev/shm

TARGET   SOURCE FSTYPE OPTIONS
/dev/shm tmpfs  tmpfs  rw,nodev,nosuid,noexec,seclabel

If the mount options for /dev/shm does not include nodev, this is a finding.'
  desc 'fix', 'Configure "/dev/shm" to mount with the "nodev" option.

Modify "/etc/fstab" to use the "nodev" option on the "/dev/shm" file system.

To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

$ sudo systemctl daemon-reload

Use the following command to apply the changes immediately without a reboot:

$ sudo mount -o remount /dev/shm'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-257863'
  tag rid: 'SV-257863r1155633_rule'
  tag stig_id: 'RHEL-09-231110'
  tag fix_id: 'F-61528r1155632_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) && command('systemd-detect-virt --container').exit_status != 0
  }

  path = '/dev/shm'
  option = 'nodev'

  describe mount(path) do
    its('options') { should include option }
  end

  describe etc_fstab.where { mount_point == path } do
    its('mount_options.flatten') { should include option }
  end
end
