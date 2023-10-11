control 'SV-257947' do
  title 'RHEL 9 must disable network management of the chrony daemon.'
  desc 'Not exposing the management interface of the chrony daemon on the network diminishes the attack space.

'
  desc 'check', 'Verify RHEL 9 disables network management of the chrony daemon with the following command:

$ grep -w cmdport /etc/chrony.conf

cmdport 0

If the "cmdport" option is not set to "0", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to disable network management of the chrony daemon by adding/modifying the following line in the /etc/chrony.conf file:

cmdport 0'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61688r925826_chk'
  tag severity: 'low'
  tag gid: 'V-257947'
  tag rid: 'SV-257947r925828_rule'
  tag stig_id: 'RHEL-09-252030'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-61612r925827_fix'
  tag satisfies: ['SRG-OS-000096-GPOS-00050', 'SRG-OS-000095-GPOS-00049']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-000382']
  tag nist: ['CM-7 a', 'CM-7 b']
end
