control 'SV-258128' do
  title 'RHEL 9 must require authentication to access emergency mode.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DOD-approved PKIs, all DOD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

This requirement prevents attackers with physical access from trivially bypassing security on the machine and gaining root access. Such accesses are further prevented by configuring the bootloader password.'
  desc 'check', 'Verify that RHEL 9 requires authentication for emergency mode with the following command:

$ grep sulogin /usr/lib/systemd/system/emergency.service 

ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency

If this line is not returned, or is commented out, this is a finding. If the output is different, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to require authentication for emergency mode.

Add or modify the following line in the "/usr/lib/systemd/system/emergency.service" file:

ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61869r926369_chk'
  tag severity: 'medium'
  tag gid: 'V-258128'
  tag rid: 'SV-258128r926371_rule'
  tag stig_id: 'RHEL-09-611195'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-61793r926370_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
