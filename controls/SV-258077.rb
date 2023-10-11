control 'SV-258077' do
  title 'RHEL 9 must terminate idle user sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended.'
  desc 'check', 'Verify that RHEL 9 logs out sessions that are idle for 15 minutes with the following command:

$ sudo grep -i ^StopIdleSessionSec /etc/systemd/logind.conf

StopIdleSessionSec=900

If "StopIdleSessionSec" is not configured to "900" seconds, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to log out idle sessions by editing the /etc/systemd/logind.conf file with the following line:

StopIdleSessionSec=900

The "logind" service must be restarted for the changes to take effect. To restart the "logind" service, run the following command:

$ sudo systemctl restart systemd-logind

Note: To preserve running user programs such as tmux, uncomment and/or edit "KillUserProccesses=no" in "/etc/systemd/logind.conf".'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61818r926216_chk'
  tag severity: 'medium'
  tag gid: 'V-258077'
  tag rid: 'SV-258077r926218_rule'
  tag stig_id: 'RHEL-09-412080'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-61742r926217_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
