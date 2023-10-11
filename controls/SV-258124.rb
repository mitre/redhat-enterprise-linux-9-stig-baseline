control 'SV-258124' do
  title 'RHEL 9 must have the pcsc-lite package installed.'
  desc 'The pcsc-lite package must be installed if it is to be available for multifactor authentication using smart cards.'
  desc 'check', 'Verify that RHEL 9 has the pcsc-lite package installed with the following command:

$ sudo dnf list --installed pcsc-lite

Example output:

pcsc-lite.x86_64          1.9.4-1.el9

If the "pcsc-lite" package is not installed, this is a finding.'
  desc 'fix', 'The  pcsc-lite  package can be installed with the following command:
 
$ sudo dnf install pcsc-lite'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61865r926357_chk'
  tag severity: 'medium'
  tag gid: 'V-258124'
  tag rid: 'SV-258124r926359_rule'
  tag stig_id: 'RHEL-09-611175'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-61789r926358_fix'
  tag 'documentable'
  tag cci: ['CCI-001948']
  tag nist: ['IA-2 (11)']
end
