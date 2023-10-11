control 'SV-258135' do
  title 'RHEL 9 must routinely check the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's information management officer (IMO)/information system security officer (ISSO) and system administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This capability must take into account operational requirements for availability for selecting an appropriate response. The organization may choose to shut down or restart the information system upon security function anomaly detection.

"
  desc 'check', 'Verify that RHEL 9 routinely executes a file integrity scan for changes to the system baseline. The command used in the example will use a daily occurrence.

Check the cron directories for scripts controlling the execution and notification of results of the file integrity application. For example, if AIDE is installed on the system, use the following commands:

$ ls -al /etc/cron.* | grep aide

-rwxr-xr-x 1 root root 29 Nov 22 2015 aide

$ grep aide /etc/crontab /var/spool/cron/root

/etc/crontab: 30 04 * * * root usr/sbin/aide
/var/spool/cron/root: 30 04 * * * root usr/sbin/aide

$ sudo more /etc/cron.daily/aide

#!/bin/bash
/usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil

If the file integrity application does not exist, or a script file controlling the execution of the file integrity application does not exist, or the file integrity application does not notify designated personnel of changes, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to run automatically on the system at least weekly and to notify designated personnel if baseline configurations are changed in an unauthorized manner. The AIDE tool can be configured to email designated personnel with the use of the cron system.
 
The following example output is generic. It will set cron to run AIDE daily and to send email at the completion of the analysis

$ sudo more /etc/cron.daily/aide
 
#!/bin/bash
/usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61876r926390_chk'
  tag severity: 'medium'
  tag gid: 'V-258135'
  tag rid: 'SV-258135r926392_rule'
  tag stig_id: 'RHEL-09-651015'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-61800r926391_fix'
  tag satisfies: ['SRG-OS-000363-GPOS-00150', 'SRG-OS-000446-GPOS-00200', 'SRG-OS-000447-GPOS-00201']
  tag 'documentable'
  tag cci: ['CCI-001744', 'CCI-002699', 'CCI-002702']
  tag nist: ['CM-3 (5)', 'SI-6 b', 'SI-6 d']
end
