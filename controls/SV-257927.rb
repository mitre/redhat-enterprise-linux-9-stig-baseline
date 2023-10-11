control 'SV-257927' do
  title 'RHEL 9 cron configuration files directory must be group-owned by root.'
  desc 'Service configuration files enable or disable features of their respective services that if configured incorrectly can lead to insecure and vulnerable configurations; therefore, service configuration files should be owned by the correct group to prevent unauthorized changes.'
  desc 'check', 'Verify the group ownership of all cron configuration files with the following command:

$ stat -c "%G %n" /etc/cron*

root /etc/cron.d
root /etc/cron.daily
root /etc/cron.deny
root /etc/cron.hourly
root /etc/cron.monthly
root /etc/crontab
root /etc/cron.weekly

If any crontab is not group owned by root, this is a finding.'
  desc 'fix', 'Configure any cron configuration not group-owned by root with the following command:

$ sudo chgrp root [cron config file]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61668r925766_chk'
  tag severity: 'medium'
  tag gid: 'V-257927'
  tag rid: 'SV-257927r925768_rule'
  tag stig_id: 'RHEL-09-232235'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61592r925767_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
