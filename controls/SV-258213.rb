control 'SV-258213' do
  title 'Successful/unsuccessful uses of the reboot command in RHEL 9 must generate an audit record.'
  desc 'Misuse of the reboot command may cause availability issues for the system.'
  desc 'check', 'Verify that RHEL 9 is configured to audit the execution of the "reboot" command with the following command:

$ sudo auditctl -l | grep reboot

-a always,exit -F path=/usr/sbin/reboot -F perm=x -F auid>=1000 -F auid!=unset -k privileged-reboot

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "reboot" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/reboot -F perm=x -F auid>=1000 -F auid!=unset -k privileged-reboot

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61954r926624_chk'
  tag severity: 'medium'
  tag gid: 'V-258213'
  tag rid: 'SV-258213r926626_rule'
  tag stig_id: 'RHEL-09-654195'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-61878r926625_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
