control 'SV-257835' do
  title 'The Trivial File Transfer Protocol (TFTP) server must not be installed unless it is required, and if required, the RHEL 9 TFTP daemon must be configured to operate in secure mode.'
  desc 'Removing the "tftp-server" package decreases the risk of the accidental (or intentional) activation of tftp services.

If TFTP is required for operational support (such as transmission of router configurations), its use must be documented with the information systems security manager (ISSM), restricted to only authorized personnel, and have access control rules established.

Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.'
  desc 'check', 'Verify if TFTP is installed, it is configured to operate in secure mode.

Note: If TFTP is not required, it must not be installed. If TFTP is not installed, this rule is not applicable.

Check to see if TFTP server is installed with the following command:

$ sudo dnf list --installed tftp-server

Updating Subscription Management repositories.
Installed Packages
tftp-server.x86_64                             5.2-38.el9                              @rhel-9-for-x86_64-appstream-rpms

Verify the TFTP daemon, if tftp.server is installed, is configured to operate in secure mode with the following command:

$ grep -i execstart /usr/lib/systemd/system/tftp.service
ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

Note: The "-s" option ensures the TFTP server only serves files from the specified directory, which is a security measure to prevent unauthorized access to other parts of the file system.'
  desc 'fix', 'Configure RHEL 9 so that TFTP operates in secure mode if installed.

If TFTP server is not required, remove it with the following command:
$ sudo dnf -y remove tftp-server

Configure the TFTP daemon to operate in secure mode with the following command:
$ sudo systemctl edit tftp.service

In the editor, enter:
[Service]
ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

After making changes, reload the systemd daemon and restart the TFTP service as follows:

$ sudo systemctl daemon-reload
$ sudo systemctl restart tftp.service

If the "-s" option is not present in the "ExecStart" line or if the line is missing, this is a finding.'
  impact 0.7
  tag check_id: 'C-61576r1155677_chk'
  tag severity: 'high'
  tag gid: 'V-257835'
  tag rid: 'SV-257835r1155679_rule'
  tag stig_id: 'RHEL-09-215060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61500r1155678_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  if input('tftp_required')
    describe package('tftp-server') do
      it { should be_installed }
    end

    describe file('/usr/lib/systemd/system/tftp.service') do
      it { should exist }
      its('content') { should match(/ExecStart=.*\s-s(\s|$)/) }
    end
  else
    describe package('tftp-server') do
      it { should_not be_installed }
    end
  end
end
