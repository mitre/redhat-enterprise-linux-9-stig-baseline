control 'SV-257875' do
  title 'RHEL 9 must mount /var/log/audit with the nosuid option.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/var/log/audit" is mounted with the "nosuid" option:

$ mount | grep /var/log/audit

/dev/mapper/rhel-var-log-audit on /var/log/audit type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/var/log/audit" file system is mounted without the "nosuid" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "nosuid" option on the "/var/log/audit" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61616r925610_chk'
  tag severity: 'medium'
  tag gid: 'V-257875'
  tag rid: 'SV-257875r925612_rule'
  tag stig_id: 'RHEL-09-231170'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61540r925611_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
