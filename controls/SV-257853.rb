control 'SV-257853' do
  title 'RHEL 9 must be configured so that the Network File System (NFS) is configured to use RPCSEC_GSS.'
  desc 'When an NFS server is configured to use RPCSEC_SYS, a selected userid and groupid are used to handle requests from the remote user. The userid and groupid could mistakenly or maliciously be set incorrectly. The RPCSEC_GSS method of authentication uses certificates on the server and client systems to more securely authenticate the remote mount request.'
  desc 'check', 'Verify RHEL 9 has the "sec" option configured for all NFS mounts with the following command:

Note: If no NFS mounts are configured, this requirement is Not Applicable.

$ cat /etc/fstab | grep nfs

192.168.22.2:/mnt/export /data nfs4 rw,nosuid,nodev,noexec,sync,soft,sec=krb5p:krb5i:krb5

If the system is mounting file systems via NFS and has the sec option without the "krb5:krb5i:krb5p" settings, the "sec" option has the "sys" setting, or the "sec" option is missing, this is a finding.'
  desc 'fix', 'Update the "/etc/fstab" file so the option "sec" is defined for each NFS mounted file system and the "sec" option does not have the "sys" setting. 

Ensure the "sec" option is defined as "krb5p:krb5i:krb5".'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61594r925544_chk'
  tag severity: 'medium'
  tag gid: 'V-257853'
  tag rid: 'SV-257853r925546_rule'
  tag stig_id: 'RHEL-09-231060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61518r925545_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
