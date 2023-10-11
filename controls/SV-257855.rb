control 'SV-257855' do
  title 'RHEL 9  must prevent code from being executed on file systems that are imported via Network File System (NFS).'
  desc 'The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary as they may be incompatible. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify RHEL 9 has the "noexec" option configured for all NFS mounts with the following command:

$ cat /etc/fstab | grep nfs

192.168.22.2:/mnt/export /data nfs4 rw,nosuid,nodev,noexec,sync,soft,sec=krb5:krb5i:krb5p

If no NFS mounts are configured, this requirement is Not Applicable.

If the system is mounting file systems via NFS and the "noexec" option is missing, this is a finding.'
  desc 'fix', 'Update each NFS mounted file system to use the "noexec" option on file systems that are being imported via NFS.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61596r925550_chk'
  tag severity: 'medium'
  tag gid: 'V-257855'
  tag rid: 'SV-257855r925552_rule'
  tag stig_id: 'RHEL-09-231070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61520r925551_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
