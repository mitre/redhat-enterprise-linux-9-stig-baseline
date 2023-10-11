control 'SV-258087' do
  title 'RHEL 9 must restrict privilege elevation to authorized personnel.'
  desc 'If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.'
  desc 'check', "Verify RHEL 9 restricts privilege elevation to authorized personnel with the following command:

$ sudo sh -c 'grep -iw ALL /etc/sudoers /etc/sudoers.d/*'

If the either of the following entries are returned, this is a finding:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL"
  desc 'fix', 'Remove the following entries from the /etc/sudoers file or configuration file under /etc/sudoers.d/:

ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61828r926246_chk'
  tag severity: 'medium'
  tag gid: 'V-258087'
  tag rid: 'SV-258087r926248_rule'
  tag stig_id: 'RHEL-09-432030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61752r926247_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
