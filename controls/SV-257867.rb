control 'SV-257867' do
  title 'RHEL 9 must mount /tmp with the noexec option.'
  desc 'The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/tmp" is mounted with the "noexec" option:

$ mount | grep /tmp

/dev/mapper/rhel-tmp on /tmp type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/tmp" file system is mounted without the "noexec" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "noexec" option on the "/tmp" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-257867'
  tag rid: 'SV-257867r958804_rule'
  tag stig_id: 'RHEL-09-231130'
  tag fix_id: 'F-61532r925587_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  path = '/tmp'
  option = 'noexec'
  mount_option_enabled = input('mount_tmp_options')[option]

  if mount_option_enabled
    describe mount(path) do
      its('options') { should include option }
    end

    describe etc_fstab.where { mount_point == path } do
      its('mount_options.flatten') { should include option }
    end
  else
    describe mount(path) do
      its('options') { should_not include option }
    end

    describe etc_fstab.where { mount_point == path } do
      its('mount_options.flatten') { should_not include option }
    end
  end
end
