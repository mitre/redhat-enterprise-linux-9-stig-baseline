control 'SV-257828' do
  title 'RHEL 9 must not have the nfs-utils package installed.'
  desc '"nfs-utils" provides a daemon for the kernel NFS server and related tools. This package also contains the "showmount" program. "showmount" queries the mount daemon on a remote host for information about the Network File System (NFS) server on the remote host. For example, "showmount" can display the clients that are mounted on that host.'
  desc 'check', 'Verify that the nfs-utils package is not installed with the following command:

$ sudo dnf list --installed nfs-utils

Error: No matching Packages to list

If the "nfs-utils" package is installed, this is a finding.'
  desc 'fix', 'Remove the nfs-utils package with the following command:

$ sudo dnf remove nfs-utils'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61569r925469_chk'
  tag severity: 'medium'
  tag gid: 'V-257828'
  tag rid: 'SV-257828r925471_rule'
  tag stig_id: 'RHEL-09-215025'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-61493r925470_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
