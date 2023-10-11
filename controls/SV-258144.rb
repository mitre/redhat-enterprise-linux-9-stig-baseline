control 'SV-258144' do
  title 'All RHEL 9 remote access methods must be monitored.'
  desc 'Logging remote access methods can be used to trace the decrease in the risks associated with remote user access management. It can also be used to spot cyberattacks and ensure ongoing compliance with organizational policies surrounding the use of remote access methods.'
  desc 'check', %q(Verify that RHEL 9 monitors all remote access methods.

Check that remote access methods are being logged by running the following command:

$ grep -rE '(auth.\*|authpriv.\*|daemon.\*)' /etc/rsyslog.conf

/etc/rsyslog.conf:authpriv.*
 
If "auth.*", "authpriv.*" or "daemon.*" are not configured to be logged, this is a finding.)
  desc 'fix', 'Add or update the following lines to the "/etc/rsyslog.conf" file:

auth.*;authpriv.*;daemon.* /var/log/secure

The "rsyslog" service must be restarted for the changes to take effect with the following command:

$ sudo systemctl restart rsyslog.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61885r926417_chk'
  tag severity: 'medium'
  tag gid: 'V-258144'
  tag rid: 'SV-258144r926419_rule'
  tag stig_id: 'RHEL-09-652030'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-61809r926418_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
