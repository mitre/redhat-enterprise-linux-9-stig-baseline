control 'SV-258060' do
  title 'RHEL 8 must ensure account lockouts persist.'
  desc 'By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.'
  desc 'check', %q(Note: This check applies to RHEL versions 8.2 or newer. If the system is
RHEL version 8.0 or 8.1, this check is not applicable.

    Verify the "/etc/security/faillock.conf" file is configured use a
non-default faillock directory to ensure contents persist after reboot:

    $ sudo grep 'dir =' /etc/security/faillock.conf

    dir = /var/log/faillock

    If the "dir" option is not set to a non-default documented tally log
directory, is missing or commented out, this is a finding.)
  desc 'fix', 'Configure the operating system maintain the contents of the faillock
directory after a reboot.

    Add/Modify the "/etc/security/faillock.conf" file to match the following
line:

    dir = /var/log/faillock'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-230339'
  tag rid: 'SV-258060r743975_rule'
  tag stig_id: 'RHEL-08-020017'
  tag fix_id: 'F-32983r743974_fix'
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
