control 'SV-257874' do
  title 'RHEL 9 must mount /var/log/audit with the noexec option.'
  desc 'The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/var/log/audit" is mounted with the "noexec" option:

$ mount | grep /var/log/audit

/dev/mapper/rhel-var-log-audit on /var/log/audit type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/var/log/audit" file system is mounted without the "noexec" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "noexec" option on the "/var/log/audit" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61615r925607_chk'
  tag severity: 'medium'
  tag gid: 'V-257874'
  tag rid: 'SV-257874r925609_rule'
  tag stig_id: 'RHEL-09-231165'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61539r925608_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
