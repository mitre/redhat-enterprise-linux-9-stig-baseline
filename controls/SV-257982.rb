control 'SV-257982' do
  title 'RHEL 9 must log SSH connection attempts and failures to the server.'
  desc 'SSH provides several logging levels with varying amounts of verbosity. "DEBUG" is specifically not recommended other than strictly for debugging SSH communications since it provides so much data that it is difficult to identify important security information. "INFO" or "VERBOSE" level is the basic level that only records login activity of SSH users. In many situations, such as Incident Response, it is important to determine when a particular user was active on a system. The logout record can eliminate those users who disconnected, which helps narrow the field.'
  desc 'check', %q(Verify RHEL 9 logs SSH connection attempts and failures to the server.

Check what the SSH daemon's "LogLevel" option is set to with the following command:

$ sudo grep -i LogLevel /etc/ssh/sshd_config

LogLevel VERBOSE

If a value of "VERBOSE" is not returned, the line is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to log connection attempts add or modify the following line in "/etc/ssh/sshd_config".

LogLevel VERBOSE

Restart the SSH daemon for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61723r925931_chk'
  tag severity: 'medium'
  tag gid: 'V-257982'
  tag rid: 'SV-257982r925933_rule'
  tag stig_id: 'RHEL-09-255030'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-61647r925932_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
