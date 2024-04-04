control 'SV-258087' do
  title 'RHEL 8 must restrict privilege elevation to authorized personnel.'
  desc 'The sudo command allows a user to execute programs with elevated
(administrator) privileges. It prompts the user for their password and confirms
your request to execute a command by checking a file, called sudoers. If the
"sudoers" file is not configured correctly, any user defined on the system
can initiate privileged actions on the target system.'
  desc 'check', %q(Verify the "sudoers" file restricts sudo access to authorized personnel.
$ sudo grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/*

If the either of the following entries are returned, this is a finding:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL)
  desc 'fix', 'Remove the following entries from the sudoers file:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-237641'
  tag rid: 'SV-258087r646893_rule'
  tag stig_id: 'RHEL-08-010382'
  tag fix_id: 'F-40823r646892_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers without sudo installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !command('sudo').exist?)
  }

  bad_sudoers_rules = sudoers(input('sudoers_config_files').join(' ')).rules.where {
    users == 'ALL' &&
      hosts == 'ALL' &&
      run_as.start_with?('ALL') &&
      commands == 'ALL'
  }

  describe 'Sudoers file(s)' do
    it 'should not contain any unrestricted sudo rules' do
      expect(bad_sudoers_rules.entries).to be_empty, "Unrestricted sudo rules found; check sudoers file(s):\n\t- #{input('sudoers_config_files').join("\n\t- ")}"
    end
  end
end
