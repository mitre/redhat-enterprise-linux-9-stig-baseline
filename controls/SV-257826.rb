control 'SV-257826' do
  title 'RHEL 9 must not have a File Transfer Protocol (FTP) server package installed.'
  desc 'The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.

Removing the "vsftpd" package decreases the risk of accidental activation.

'
  desc 'check', 'Verify that RHEL 9 does not have a File Transfer Protocol (FTP) server package installed with the following command:

$ sudo dnf list --installed | grep ftp 

If the "ftp" package is installed, this is a finding.'
  desc 'fix', 'The ftp package can be removed with the following command (using vsftpd as an example):

$ sudo dnf remove vsftpd'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61567r925463_chk'
  tag severity: 'high'
  tag gid: 'V-257826'
  tag rid: 'SV-257826r925465_rule'
  tag stig_id: 'RHEL-09-215015'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-61491r925464_fix'
  tag satisfies: ['SRG-OS-000074-GPOS-00042', 'SRG-OS-000095-GPOS-00049', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000197', 'CCI-000366', 'CCI-000381']
  tag nist: ['IA-5 (1) (c)', 'CM-6 b', 'CM-7 a']
end
