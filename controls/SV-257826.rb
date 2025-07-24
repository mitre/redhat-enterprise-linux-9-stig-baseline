control 'SV-257826' do
  title 'RHEL 9 must not have a File Transfer Protocol (FTP) server package installed.'
  desc 'The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.

Removing the "vsftpd" package decreases the risk of accidental activation.'
  desc 'check', 'Verify that RHEL 9 does not have a File Transfer Protocol (FTP) server package installed with the following command:

$ rpm -q vsftpd

package vsftpd is not installed 

If the "ftp" package is installed, this is a finding.'
  desc 'fix', 'The ftp package can be removed with the following command (using vsftpd as an example):

$ sudo dnf remove vsftpd'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag gid: 'V-257826'
  tag rid: 'SV-257826r1044890_rule'
  tag stig_id: 'RHEL-09-215015'
  tag fix_id: 'F-61491r925464_fix'
  tag cci: ['CCI-000366', 'CCI-000197', 'CCI-000381']
  tag nist: ['CM-6 b', 'IA-5 (1) (c)', 'CM-7 a']
  tag 'host'
  tag 'container'

  if input('ftp_required')
    describe package('vsftpd') do
      it { should be_installed }
    end
  else
    describe package('vsftpd') do
      it { should_not be_installed }
    end
  end
end
