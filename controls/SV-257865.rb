control 'SV-257865' do
  title 'RHEL 9 must mount /dev/shm with the nosuid option.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/dev/shm" is mounted with the "nosuid" option with the following command:

$ mount | grep /dev/shm

tmpfs on /dev/shm type tmpfs (rw,nodev,nosuid,noexec,seclabel)

If the /dev/shm file system is mounted without the "noexec" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "nosuid" option on the "/dev/shm" file system.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61606r925580_chk'
  tag severity: 'medium'
  tag gid: 'V-257865'
  tag rid: 'SV-257865r925582_rule'
  tag stig_id: 'RHEL-09-231120'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61530r925581_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
