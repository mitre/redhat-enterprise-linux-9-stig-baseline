control 'SV-258091' do
  title 'RHEL 8 systems, version 8.4 and above, must ensure the password complexity module is configured for three retries or less.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

RHEL 8 utilizes "pwquality" as a mechanism to enforce password complexity. This is set in both:
/etc/pam.d/password-auth
/etc/pam.d/system-auth
By limiting the number of attempts to meet the pwquality module complexity requirements before returning with an error, the system will audit abnormal attempts at password changes.'
  desc 'check', 'Note: This requirement applies to RHEL versions 8.4 or newer. If the system is RHEL below version 8.4, this requirement is not applicable.

Verify the operating system is configured to limit the "pwquality" retry option to 3.

Check for the use of the "pwquality" retry option with the following command:

$ sudo grep -r retry /etc/security/pwquality.conf*

/etc/security/pwquality.conf:retry = 3

If the value of "retry" is set to "0" or greater than "3", is commented out or missing, this is a finding.

If conflicting results are returned, this is a finding.

Check for the use of the "pwquality" retry option in the system-auth and password-auth files with the following command:

$ sudo grep pwquality /etc/pam.d/system-auth /etc/pam.d/password-auth | grep retry

If the command returns any results, this is a finding.'
  desc 'fix', 'Configure the operating system to limit the "pwquality" retry option to 3.

Add the following line to the "/etc/security/pwquality.conf" file(or modify the line to have the required value):

retry = 3

Remove any configurations that conflict with the above value.'
  impact 0.5
  tag check_id: 'C-55153r858735_chk'
  tag severity: 'medium'
  tag gid: 'V-251716'
  tag rid: 'SV-258091r858737_rule'
  tag stig_id: 'RHEL-08-020104'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55107r858736_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  only_if('This requirement only applies to RHEL 8 versions above 8.4', impact: 0.0) {
    os.release.to_f >= 8.4
  }

  describe 'System pwquality setting' do
    subject { parse_config(command('grep -rh retry /etc/security/pwquality.conf*').stdout.strip) }
    its('retry') { should cmp >= input('min_retry') }
  end
end
