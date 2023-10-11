control 'SV-257835' do
  title 'RHEL 9 must not have a Trivial File Transfer Protocol (TFTP) server package installed.'
  desc 'Removing the "tftp-server" package decreases the risk of the accidental (or intentional) activation of tftp services.

If TFTP is required for operational support (such as transmission of router configurations), its use must be documented with the information systems security manager (ISSM), restricted to only authorized personnel, and have access control rules established.'
  desc 'check', 'Verify that RHEL 9 does not have a tftp server package installed with the following command:

$ sudo dnf list --installed | grep tftp 

If the "tftp" package is installed, this is a finding.'
  desc 'fix', 'The tftp package can be removed with the following command:

$ sudo dnf remove tftp'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61576r925490_chk'
  tag severity: 'high'
  tag gid: 'V-257835'
  tag rid: 'SV-257835r925492_rule'
  tag stig_id: 'RHEL-09-215060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61500r925491_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
