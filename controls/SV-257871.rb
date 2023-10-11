control 'SV-257871' do
  title 'RHEL 9 must mount /var/log with the noexec option.'
  desc 'The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/var/log" is mounted with the "noexec" option:

$ mount | grep /var/log

/dev/mapper/rhel-var-log on /var/log type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/var/log" file system is mounted without the "noexec" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "noexec" option on the "/var/log" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61612r925598_chk'
  tag severity: 'medium'
  tag gid: 'V-257871'
  tag rid: 'SV-257871r925600_rule'
  tag stig_id: 'RHEL-09-231150'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61536r925599_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
