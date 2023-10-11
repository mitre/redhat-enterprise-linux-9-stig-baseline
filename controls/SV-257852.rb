control 'SV-257852' do
  title 'RHEL 9 must prevent code from being executed on file systems that contain user home directories.'
  desc 'The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/home" is mounted with the "noexec" option with the following command:

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is automatically a finding, as the "noexec" option cannot be used on the "/" system.

$ mount | grep /home

tmpfs on /home type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/home" file system is mounted without the "noexec" option, this is a finding.'
  desc 'fix', 'Modify "/etc/fstab" to use the "noexec" option on the "/home" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61593r925541_chk'
  tag severity: 'medium'
  tag gid: 'V-257852'
  tag rid: 'SV-257852r925543_rule'
  tag stig_id: 'RHEL-09-231055'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61517r925542_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
