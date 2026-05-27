control 'SV-258077' do
  title 'RHEL 9 must terminate idle user sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended.'
  desc 'check', 'Verify RHEL 9 logs out sessions that are idle for 10 minutes with the following command:

$ systemd-analyze cat-config systemd/logind.conf | grep StopIdleSessionSec

#StopIdleSessionSec=infinity
StopIdleSessionSec=600

If "StopIdleSessionSec" is not configured to "600" seconds, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to log out idle sessions.

Create the directory if necessary:

$ mkdir -p /etc/systemd/logind.conf.d/

Create a *.conf file in /etc/systemd/logind.conf.d/ with the following content:

[Login]
StopIdleSessionSec=600
KillUserProcesses=no

Restart systemd-logind:

$ systemctl restart systemd-logind'
  impact 0.5
  tag check_id: 'C-61818r1155657_chk'
  tag severity: 'medium'
  tag gid: 'V-258077'
  tag rid: 'SV-258077r1155659_rule'
  tag stig_id: 'RHEL-09-412080'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-61742r1155658_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
  tag 'container'
  tag 'host'

  stop_idle_session_sec = input('stop_idle_session_sec')

  describe parse_config_file('/etc/systemd/logind.conf') do
    its('Login') { should include('StopIdleSessionSec' => stop_idle_session_sec.to_s) }
  end
end
