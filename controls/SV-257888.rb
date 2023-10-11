control 'SV-257888' do
  title 'RHEL 9 cron configuration directories must have a mode of 0700 or less permissive.'
  desc 'Service configuration files enable or disable features of their respective services that if configured incorrectly can lead to insecure and vulnerable configurations. Therefore, service configuration files should have the correct access rights to prevent unauthorized changes.'
  desc 'check', 'Verify the permissions of the cron directories with the following command:

$ find /etc/cron* -type d | xargs stat -c "%a %n"

700 /etc/cron.d
700 /etc/cron.daily
700 /etc/cron.hourly
700 /etc/cron.monthly
700 /etc/cron.weekly

If any cron configuration directory is more permissive than "700", this is a finding.'
  desc 'fix', 'Configure any RHEL 9 cron configuration directory with a mode more permissive than "0700" as follows:

chmod 0700 [cron configuration directory]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61629r925649_chk'
  tag severity: 'medium'
  tag gid: 'V-257888'
  tag rid: 'SV-257888r925651_rule'
  tag stig_id: 'RHEL-09-232040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61553r925650_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
