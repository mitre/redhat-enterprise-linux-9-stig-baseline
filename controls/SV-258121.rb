control 'SV-258121' do
  title 'RHEL 9 must use the CAC smart card driver.'
  desc 'Smart card login provides two-factor authentication stronger than that provided by a username and password combination. Smart cards leverage public key infrastructure to provide and verify credentials. Configuring the smart card driver in use by the organization helps to prevent users from using unauthorized smart cards.

'
  desc 'check', 'Verify that RHEL loads the CAC driver with the following command:

$ grep card_drivers /etc/opensc.conf

card_drivers = cac; 

If "cac" is not listed as a card driver, or there is no line returned for "card_drivers", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to load the CAC driver.

Add or modify the following line in the "/etc/opensc.conf" file:

card_drivers = cac;'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61862r926348_chk'
  tag severity: 'medium'
  tag gid: 'V-258121'
  tag rid: 'SV-258121r926350_rule'
  tag stig_id: 'RHEL-09-611160'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-61786r926349_fix'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000109-GPOS-00056', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-000766', 'CCI-000767', 'CCI-000768', 'CCI-000770', 'CCI-001941', 'CCI-001942']
  tag nist: ['IA-2', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (5)', 'IA-2 (8)', 'IA-2 (9)']
end
