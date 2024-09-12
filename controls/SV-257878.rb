control 'SV-257878' do
  title 'RHEL 9 must mount /var/tmp with the nosuid option.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/var/tmp" is mounted with the "nosuid" option:

$ mount | grep /var/tmp

/dev/mapper/rhel-var-tmp on /var/tmp type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/var/tmp" file system is mounted without the "nosuid" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "nosuid" option on the "/var/tmp" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-257878'
  tag rid: 'SV-257878r958804_rule'
  tag stig_id: 'RHEL-09-231185'
  tag fix_id: 'F-61543r925620_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  path = '/var/tmp'
  option = 'nosuid'

  describe mount(path) do
    its('options') { should include option }
  end

  describe etc_fstab.where { mount_point == path } do
    its('mount_options.flatten') { should include option }
  end
end
