control 'SV-257870' do
  title 'RHEL 9 must mount /var/log with the nodev option.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', 'Verify "/var/log" is mounted with the "nodev" option:

$ mount | grep /var/log

/dev/mapper/rhel-var-log on /var/log type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/var/log" file system is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "nodev" option on the "/var/log" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-257870'
  tag rid: 'SV-257870r958804_rule'
  tag stig_id: 'RHEL-09-231145'
  tag fix_id: 'F-61535r925596_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  path = '/var/log'
  option = 'nodev'

  describe mount(path) do
    its('options') { should include option }
  end

  describe etc_fstab.where { mount_point == path } do
    its('mount_options.flatten') { should include option }
  end
end
