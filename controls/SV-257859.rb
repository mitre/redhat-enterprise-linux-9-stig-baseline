control 'SV-257859' do
  title 'RHEL 9 must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media.'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify file systems that are used for removable media are mounted with the "nosuid" option with the following command:

$ more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid,nodev,noexec 0 0

If a file system found in "/etc/fstab" refers to removable media and it does not have the "nosuid" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on file systems that are associated with removable media.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61600r925562_chk'
  tag severity: 'medium'
  tag gid: 'V-257859'
  tag rid: 'SV-257859r925564_rule'
  tag stig_id: 'RHEL-09-231090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61524r925563_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
