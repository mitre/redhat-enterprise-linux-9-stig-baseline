control 'SV-258060' do
  title 'RHEL 9 must ensure account lockouts persist.'
  desc 'Having lockouts persist across reboots ensures that account is only unlocked by an administrator. If the lockouts did not persist across reboots, an attacker could simply reboot the system to continue brute force attacks against the accounts on the system.'
  desc 'check', %q(Verify the "/etc/security/faillock.conf" file is configured use a nondefault faillock directory to ensure contents persist after reboot with the following command:

$ grep 'dir =' /etc/security/faillock.conf

dir = /var/log/faillock

If the "dir" option is not set to a nondefault documented tally log directory, is missing or commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 9 maintain the contents of the faillock directory after a reboot.

Add/modify the "/etc/security/faillock.conf" file to match the following line:

dir = /var/log/faillock'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-258060'
  tag rid: 'SV-258060r926167_rule'
  tag stig_id: 'RHEL-09-411105'
  tag fix_id: 'F-61725r926166_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
  tag 'host'
  tag 'container'

  only_if('This check applies to RHEL versions 8.2 or newer. If the system is RHEL version 8.0 or 8.1, this check is not applicable.', impact: 0.0) {
    (os.release.to_f) >= 8.2
  }

  describe parse_config_file('/etc/security/faillock.conf') do
    its('dir') { should cmp input('log_directory') }
  end
end
