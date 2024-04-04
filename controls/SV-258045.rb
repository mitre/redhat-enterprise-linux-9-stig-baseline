control 'SV-258045' do
  title 'RHEL 8 duplicate User IDs (UIDs) must not exist for interactive users.'
  desc 'To ensure accountability and prevent unauthenticated access,
interactive users must be identified and authenticated to prevent potential
misuse and compromise of the system.

    Interactive users include organizational employees or individuals the
organization deems to have equivalent status of employees (e.g., contractors).
Interactive users (and processes acting on behalf of users) must be uniquely
identified and authenticated to all accesses, except for the following:

    1) Accesses explicitly identified and documented by the organization.
Organizations document specific user actions that can be performed on the
information system without identification or authentication; and

    2) Accesses that occur through authorized use of group authenticators
without individual authentication. Organizations may require unique
identification of individuals in group accounts (e.g., shared privilege
accounts) or for detailed accountability of individual activity.'
  desc 'check', %q(Verify that RHEL 8 contains no duplicate User IDs (UIDs) for interactive
users.

    Check that the operating system contains no duplicate UIDs for interactive
users with the following command:

    $ sudo awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

    If output is produced, and the accounts listed are interactive user
accounts, this is a finding.)
  desc 'fix', 'Edit the file "/etc/passwd" and provide each interactive user
account that has a duplicate User ID (UID) with a unique UID.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000121-GPOS-00062', 'SRG-OS-000042-GPOS-00020']
  tag gid: 'V-230371'
  tag rid: 'SV-258045r627750_rule'
  tag stig_id: 'RHEL-08-020240'
  tag fix_id: 'F-33015r567860_fix'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
  tag 'host'
  tag 'container'

  user_count = passwd.where { uid.to_i >= 1000 }.entries.length

  describe "Count of interactive unique user IDs should match interactive user count (#{user_count}): UID count" do
    subject { passwd.where { uid.to_i >= 1000 }.uids.uniq.length }
    it { should eq user_count }
  end
end
