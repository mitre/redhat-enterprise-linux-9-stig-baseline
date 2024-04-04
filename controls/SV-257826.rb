control 'SV-257826' do
  title 'A File Transfer Protocol (FTP) server package must not be installed
unless mission essential on RHEL 8.'
  desc 'The FTP service provides an unencrypted remote access that does not
provide for the confidentiality and integrity of user passwords or the remote
session. If a privileged user were to log on using this service, the privileged
user password could be compromised. SSH or other encrypted file transfer
methods must be used in place of this service.'
  desc 'check', 'Verify an FTP server has not been installed on the system with the
following commands:

    $ sudo yum list installed *ftpd*

    vsftpd.x86_64
3.0.3-28.el8                                                  appstream

    If an FTP server is installed and is not documented with the Information
System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Document the FTP server package with the ISSO as an operational requirement
or remove it from the system with the following command:

    $ sudo yum remove vsftpd'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230558'
  tag rid: 'SV-257826r627750_rule'
  tag stig_id: 'RHEL-08-040360'
  tag fix_id: 'F-33202r568421_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
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
