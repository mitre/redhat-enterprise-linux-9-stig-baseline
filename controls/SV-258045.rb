control 'SV-258045' do
  title 'RHEL 9 duplicate User IDs (UIDs) must not exist for interactive users.'
  desc 'To ensure accountability and prevent unauthenticated access, interactive users must be identified and authenticated to prevent potential misuse and compromise of the system.'
  desc 'check', %q(Verify that RHEL 9 contains no duplicate UIDs for interactive users with the following command:

$ sudo awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

If output is produced and the accounts listed are interactive user accounts, this is a finding.)
  desc 'fix', 'Edit the file "/etc/passwd" and provide each interactive user account that has a duplicate UID with a unique UID.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000121-GPOS-00062', 'SRG-OS-000042-GPOS-00020']
  tag gid: 'V-258045'
  tag rid: 'SV-258045r926122_rule'
  tag stig_id: 'RHEL-09-411030'
  tag fix_id: 'F-61710r926121_fix'
  tag cci: ['CCI-000764', 'CCI-000135', 'CCI-000804']
  tag nist: ['IA-2', 'AU-3 (1)', 'IA-8']
  tag 'host'
  tag 'container'

  user_count = passwd.where { uid.to_i >= 1000 }.entries.length

  describe "Count of interactive unique user IDs should match interactive user count (#{user_count}): UID count" do
    subject { passwd.where { uid.to_i >= 1000 }.uids.uniq.length }
    it { should eq user_count }
  end
end
