control 'SV-258047' do
  title 'RHEL 9 must automatically expire temporary accounts within 72 hours.'
  desc 'Temporary accounts are privileged or nonprivileged accounts that are
    established during pressing circumstances, such as new software or hardware
    configuration or an incident response, where the need for prompt account
    activation requires bypassing normal account authorization procedures.

    If any inactive temporary accounts are left enabled on the system and are
    not either manually removed or automatically expired within 72 hours, the
    security posture of the system will be degraded and exposed to exploitation
    by unauthorized users or insider threat actors.

    Temporary accounts are different from emergency accounts. Emergency accounts,
    also known as "last resort" or "break glass" accounts, are local logon accounts
    enabled on the system for emergency use by authorized system administrators
    to manage a system when standard logon methods are failing or not available.

    Emergency accounts are not subject to manual removal or scheduled expiration
    requirements.

    The automatic expiration of temporary accounts may be extended as needed by
    the circumstances but it must not be extended indefinitely. A documented
    permanent account should be established for privileged users who need long-term
    maintenance accounts.'
  desc 'check', 'Verify temporary accounts have been provisioned with an
    expiration date of 72 hours.

    For every existing temporary account, run the following command to obtain its
    account expiration information:

    $ sudo chage -l <temporary_account_name> | grep -i "account expires"

    Verify each of these accounts has an expiration date set within 72 hours.

    If any temporary accounts have no expiration date set or do not expire within
    72 hours, this is a finding.'
  desc 'fix', 'Configure the operating system to expire temporary accounts after
    72 hours with the following command:

    $ sudo chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag gid: 'V-258047'
  tag rid: 'SV-258047r926128_rule'
  tag stig_id: 'RHEL-09-411040'
  tag fix_id: 'F-61712r926127_fix'
  tag cci: ['CCI-001682', 'CCI-000016']
  tag nist: ['AC-2 (2)']
  tag 'host'
  tag 'container'

  tmp_users = input('temporary_accounts')

  # NOTE: that 230331 is extremely similar to this req, to the point where this input seems
  # appropriate to use for both of them
  tmp_max_days = input('temporary_account_max_days')

  if tmp_users.empty?
    describe 'Temporary accounts' do
      subject { tmp_users }
      it { should be_empty }
    end
  else
    # user has to specify what the tmp accounts are, so we will print a different pass message
    # if none of those tmp accounts even exist on the system for clarity
    tmp_users_existing = tmp_users.select { |u| user(u).exists? }
    failing_users = tmp_users_existing.select { |u| user(u).warndays > tmp_max_days }

    describe 'Temporary accounts' do
      if tmp_users_existing.nil?
        it "should have expiration times less than or equal to '#{tmp_max_days}' days" do
          expect(failing_users).to be_empty, "Failing users:\n\t- #{failing_users.join("\n\t- ")}"
        end
      else
        it "(input as '#{tmp_users.join("', '")}') were not found on this system" do
          expect(tmp_users_existing).to be_empty
        end
      end
    end
  end
end
