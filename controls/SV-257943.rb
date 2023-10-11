control 'SV-257943' do
  title 'RHEL 9 must have the chrony package installed.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.'
  desc 'check', 'Verify that RHEL 9 has the chrony package installed with the following command:

$ sudo dnf list --installed chrony

Example output:

chrony.x86_64          4.1-3.el9       

If the "chrony" package is not installed, this is a finding.'
  desc 'fix', 'The chrony package can be installed with the following command:
 
$ sudo dnf install chrony'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61684r925814_chk'
  tag severity: 'medium'
  tag gid: 'V-257943'
  tag rid: 'SV-257943r925816_rule'
  tag stig_id: 'RHEL-09-252010'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-61608r925815_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
