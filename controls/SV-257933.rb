control 'SV-257933' do
  title 'RHEL 9 /etc/crontab file must have mode 0600.'
  desc 'Service configuration files enable or disable features of their respective services that if configured incorrectly can lead to insecure and vulnerable configurations; therefore, service configuration files must have the correct access rights to prevent unauthorized changes.'
  desc 'check', 'Verify the permissions of /etc/crontab with the following command:

$ stat -c "%a %n" /etc/crontab

0600

If /etc/crontab does not have a mode of "0600", this is a finding.'
  desc 'fix', 'Configure the RHEL 9 file /etc/crontab with mode 600.

$ sudo chmod 0600 /etc/crontab'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61674r925784_chk'
  tag severity: 'medium'
  tag gid: 'V-257933'
  tag rid: 'SV-257933r925786_rule'
  tag stig_id: 'RHEL-09-232265'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61598r925785_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
