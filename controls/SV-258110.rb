control 'SV-258110' do
  title 'RHEL 9 must prevent the use of dictionary words for passwords.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If RHEL 9 allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses, and brute-force attacks.'
  desc 'check', 'Verify RHEL 9 prevents the use of dictionary words for passwords with the following command:

$ sudo grep dictcheck /etc/security/pwquality.conf /etc/pwquality.conf.d/*.conf 

/etc/security/pwquality.conf:dictcheck=1 

If "dictcheck" does not have a value other than "0", or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to prevent the use of dictionary words for passwords.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the /etc/pwquality.conf.d/ directory to contain the "dictcheck" parameter:

dictcheck=1'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61851r926315_chk'
  tag severity: 'medium'
  tag gid: 'V-258110'
  tag rid: 'SV-258110r926317_rule'
  tag stig_id: 'RHEL-09-611105'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-61775r926316_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
