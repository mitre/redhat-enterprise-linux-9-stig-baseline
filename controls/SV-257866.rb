control 'SV-257866' do
  title 'RHEL 9 must mount /tmp with the nodev option.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', 'Verify "/tmp" is mounted with the "nodev" option:

$ mount | grep /tmp

/dev/mapper/rhel-tmp on /tmp type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/tmp" file system is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "nodev" option on the "/tmp" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61607r925583_chk'
  tag severity: 'medium'
  tag gid: 'V-257866'
  tag rid: 'SV-257866r925585_rule'
  tag stig_id: 'RHEL-09-231125'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61531r925584_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
