control 'SV-257978' do
  title 'All RHEL 9 networked systems must have SSH installed.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

'
  desc 'check', 'Verify that RHEL 9 has the openssh-server package installed with the following command:

$ sudo dnf list --installed openssh-server

Example output:

openssh-server.x86_64          8.7p1-8.el9

If the "openssh-server" package is not installed, this is a finding.'
  desc 'fix', 'The openssh-server package can be installed with the following command:
 
$ sudo dnf install openssh-server'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61719r925919_chk'
  tag severity: 'medium'
  tag gid: 'V-257978'
  tag rid: 'SV-257978r925921_rule'
  tag stig_id: 'RHEL-09-255010'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-61643r925920_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']
end
