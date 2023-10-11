control 'SV-258071' do
  title 'RHEL 9 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Increasing the time between a failed authentication attempt and reprompting to enter credentials helps to slow a single-threaded brute force attack.'
  desc 'check', 'Verify RHEL 9 enforces a delay of at least four seconds between console logon prompts following a failed logon attempt with the following command:

$ grep -i fail_delay /etc/login.defs

FAIL_DELAY 4

If the value of "FAIL_DELAY" is not set to "4" or greater, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the RHEL 9 to enforce a delay of at least four seconds between logon prompts following a failed console logon attempt.

Modify the "/etc/login.defs" file to set the "FAIL_DELAY" parameter to 4 or greater:

FAIL_DELAY 4'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61812r926198_chk'
  tag severity: 'medium'
  tag gid: 'V-258071'
  tag rid: 'SV-258071r926200_rule'
  tag stig_id: 'RHEL-09-412050'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-61736r926199_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
