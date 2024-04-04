control 'SV-258095' do
  title 'RHEL 8 must configure the use of the pam_faillock.so module in the
/etc/pam.d/system-auth file.'
  desc 'By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module. Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.
    The preauth argument must be used when the module is called before the
modules which ask for the user credentials such as the password.'
  desc 'check', 'Note: This check applies to RHEL versions 8.2 or newer, if the system is
RHEL version 8.0 or 8.1, this check is not applicable.

    Verify the pam_faillock.so module is present in the
"/etc/pam.d/system-auth" file:

    $ sudo grep pam_faillock.so /etc/pam.d/system-auth

    auth               required                               pam_faillock.so
preauth
    auth               required                               pam_faillock.so
authfail
    account        required                                pam_faillock.so
    If the pam_faillock.so module is not present in the
"/etc/pam.d/system-auth" file with the "preauth" line listed before
pam_unix.so, this is a finding.'
  desc 'fix', 'Configure the operating system to include the use of the pam_faillock.so
module in the /etc/pam.d/system-auth file.

    Add/Modify the appropriate sections of the "/etc/pam.d/system-auth" file
to match the following lines:
    Note: The "preauth" line must be listed before pam_unix.so.

    auth required pam_faillock.so preauth
    auth required pam_faillock.so authfail
    account required pam_faillock.so'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-244533'
  tag rid: 'SV-258095r743848_rule'
  tag stig_id: 'RHEL-08-020025'
  tag fix_id: 'F-47765r743847_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
  tag 'host'
  tag 'container'

  only_if('This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.', impact: 0.0) {
    (os.release.to_f) >= 8.2
  }

  pam_auth_files = input('pam_auth_files')

  describe pam(pam_auth_files['system-auth']) do
    its('lines') { should match_pam_rule('auth required pam_faillock.so preauth') }
    its('lines') { should match_pam_rule('auth required pam_faillock.so authfail') }
    its('lines') { should match_pam_rule('account required pam_faillock.so') }
  end
end
