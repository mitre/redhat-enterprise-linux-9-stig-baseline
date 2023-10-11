control 'SV-258003' do
  title 'RHEL 9 SSH daemon must not allow GSSAPI authentication.'
  desc "Generic Security Service Application Program Interface (GSSAPI) authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system.

"
  desc 'check', 'Verify the SSH daemon does not allow GSSAPI authentication with the following command:

$ sudo grep -ir gssapiauth  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*

GSSAPIAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, and the use of GSSAPI authentication has not been documented with the information system security officer (ISSO), this is a finding.

If the required value is not set, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to not allow GSSAPI authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "no":

GSSAPIAuthentication no

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61744r925994_chk'
  tag severity: 'medium'
  tag gid: 'V-258003'
  tag rid: 'SV-258003r925996_rule'
  tag stig_id: 'RHEL-09-255135'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-61668r925995_fix'
  tag satisfies: ['SRG-OS-000364-GPOS-00151', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001813']
  tag nist: ['CM-6 b', 'CM-5 (1) (a)']
end
