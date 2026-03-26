control 'SV-257865' do
  title 'RHEL 9 must mount /dev/shm with the nosuid option.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/dev/shm" is mounted with the "nosuid" option with the following command:

$ findmnt /dev/shm

/dev/shm tmpfs  tmpfs  rw,nodev,nosuid,noexec,seclabel

If the mount options for /dev/shm does not include nosuid, this is a finding.'
  desc 'fix', 'Configure "/dev/shm" to mount with the "nosuid" option.

Modify "/etc/fstab" to use the "nosuid" option on the "/dev/shm" file system.

To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

$ sudo systemctl daemon-reload

Use the following command to apply the changes immediately without a reboot:

$ sudo mount -o remount /dev/shm'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-257865'
  tag rid: 'SV-257865r1155636_rule'
  tag stig_id: 'RHEL-09-231120'
  tag fix_id: 'F-61530r1155635_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  path = '/dev/shm'
  option = 'nosuid'

  describe mount(path) do
    its('options') { should include option }
  end

  describe etc_fstab.where { mount_point == path } do
    its('mount_options.flatten') { should include option }
  end
end
