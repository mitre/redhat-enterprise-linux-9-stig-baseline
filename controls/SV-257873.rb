control 'SV-257873' do
  title 'RHEL 9 must mount /var/log/audit with the nodev option.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', 'Verify "/var/log/audit" is mounted with the "nodev" option:

$ mount | grep /var/log/audit

/dev/mapper/rhel-var-log-audit on /var/log/audit type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/var/log/audit" file system is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "nodev" option on the "/var/log/audit" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61614r925604_chk'
  tag severity: 'medium'
  tag gid: 'V-257873'
  tag rid: 'SV-257873r925606_rule'
  tag stig_id: 'RHEL-09-231160'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61538r925605_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
