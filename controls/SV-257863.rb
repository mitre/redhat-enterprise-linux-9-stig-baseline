control 'SV-257863' do
  title 'RHEL 9 must mount /dev/shm with the nodev option.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', 'Verify "/dev/shm" is mounted with the "nodev" option with the following command:

$ mount | grep /dev/shm

tmpfs on /dev/shm type tmpfs (rw,nodev,nosuid,noexec,seclabel)

If the /dev/shm file system is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "nodev" option on the "/dev/shm" file system.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61604r925574_chk'
  tag severity: 'medium'
  tag gid: 'V-257863'
  tag rid: 'SV-257863r925576_rule'
  tag stig_id: 'RHEL-09-231110'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61528r925575_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
