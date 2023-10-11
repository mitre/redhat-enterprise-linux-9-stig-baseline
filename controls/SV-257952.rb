control 'SV-257952' do
  title 'If the Trivial File Transfer Protocol (TFTP) server is required, RHEL 9 TFTP daemon must be configured to operate in secure mode.'
  desc 'Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files. Using the "-s" option causes the TFTP service to only serve files from the given directory.'
  desc 'check', 'Verify the TFTP daemon is configured to operate in secure mode.

Check if a TFTP server is installed with the following command:

$ sudo dnf list --installed tftp-server

Example output:

tftp-server.x86_64          5.2-35.el9.x86_64

Note: If a TFTP server is not installed, this requirement is Not Applicable.

If a TFTP server is installed, check for the server arguments with the following command: 

$ systemctl cat tftp | grep ExecStart
ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

If the "ExecStart" line does not have a "-s" option, and a subdirectory is not assigned, this is a finding.'
  desc 'fix', 'Configure the TFTP daemon to operate in secure mode.

1. Find the path for the systemd service.

$ sudo systemctl show tftp | grep FragmentPath=
FragmentPath=/etc/systemd/system/tftp.service

2. Edit the ExecStart line on that file to add the -s option with a subdirectory.

ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61693r925841_chk'
  tag severity: 'medium'
  tag gid: 'V-257952'
  tag rid: 'SV-257952r925843_rule'
  tag stig_id: 'RHEL-09-252055'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61617r925842_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
