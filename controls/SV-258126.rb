control 'SV-258126' do
  title 'RHEL 9 must have the opensc package installed.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

The DOD has mandated the use of the Common Access Card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.

'
  desc 'check', 'Verify that RHEL 9 has the opensc package installed with the following command:

$ sudo dnf list --installed opensc

Example output:

opensc.x86_64          0.22.0-2.el9

If the "opensc" package is not installed, this is a finding.'
  desc 'fix', 'The opensc package can be installed with the following command:
 
$ sudo dnf install opensc'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61867r926363_chk'
  tag severity: 'medium'
  tag gid: 'V-258126'
  tag rid: 'SV-258126r926365_rule'
  tag stig_id: 'RHEL-09-611185'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-61791r926364_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000376-GPOS-00161']
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-001953']
  tag nist: ['IA-2 (11)', 'IA-2 (12)']
end
