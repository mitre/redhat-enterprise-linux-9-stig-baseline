control 'SV-257851' do
  title 'RHEL 9 must prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

'
  desc 'check', 'Verify "/home" is mounted with the "nosuid" option with the following command:

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is automatically a finding, as the "nosuid" option cannot be used on the "/" system.

$ mount | grep /home

tmpfs on /home type tmpfs (rw,nodev,nosuid,noexec,seclabel)

If the "/home" file system is mounted without the "nosuid" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "nosuid" option on the "/home" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61592r925538_chk'
  tag severity: 'medium'
  tag gid: 'V-257851'
  tag rid: 'SV-257851r925540_rule'
  tag stig_id: 'RHEL-09-231050'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61516r925539_fix'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001764']
  tag nist: ['CM-6 b', 'CM-7 (2)']
end
