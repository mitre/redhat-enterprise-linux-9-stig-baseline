control 'SV-257868' do
  title 'RHEL 9 must mount /tmp with the nosuid option.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/tmp" is mounted with the "nosuid" option:

$ mount | grep /tmp

/dev/mapper/rhel-tmp on /tmp type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/tmp" file system is mounted without the "nosuid" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "nosuid" option on the "/tmp" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61609r925589_chk'
  tag severity: 'medium'
  tag gid: 'V-257868'
  tag rid: 'SV-257868r925591_rule'
  tag stig_id: 'RHEL-09-231135'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61533r925590_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
