control 'SV-258143' do
  title 'RHEL 9 must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation.'
  desc "Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information into the system's logs, or could fill the system's storage leading to a denial of service.

If the system is intended to be a log aggregation server, its use must be documented with the information system security officer (ISSO)."
  desc 'check', 'Verify that RHEL 9 is not configured to receive remote logs using rsyslog with the following commands:

$ grep -i modload /etc/rsyslog.conf /etc/rsyslog.d/*
$ModLoad imtcp
$ModLoad imrelp

$ grep -i serverrun /etc/rsyslog.conf /etc/rsyslog.d/*
$InputTCPServerRun 514
$InputRELPServerRun 514

Note: An error about no files or directories may be returned. This is not a finding.

If any lines are returned by the command, then rsyslog is configured to receive remote messages, and this is a finding.'
  desc 'fix', 'Configure RHEL 9 to not receive remote logs using rsyslog.

Remove the lines in /etc/rsyslog.conf and any files in the /etc/rsyslog.d directory that match any of the following:

$ModLoad imtcp
$ModLoad imudp
$ModLoad imrelp
$InputTCPServerRun [0-9]*
$UDPServerRun [0-9]*
$InputRELPServerRun [0-9]*

The rsyslog daemon must be restarted for the changes to take effect:

$ sudo systemctl restart rsyslog.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61884r926414_chk'
  tag severity: 'medium'
  tag gid: 'V-258143'
  tag rid: 'SV-258143r926416_rule'
  tag stig_id: 'RHEL-09-652025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61808r926415_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
