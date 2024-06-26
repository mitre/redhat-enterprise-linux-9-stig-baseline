control 'SV-257934' do
  title 'RHEL 9 /etc/shadow file must have mode 0000 to prevent unauthorized access.'
  desc 'The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information, which could weaken the system security posture.'
  desc 'check', 'Verify that the "/etc/shadow" file has mode "0000" with the following command:

$ sudo stat -c "%a %n" /etc/shadow

0 /etc/shadow

If a value of "0" is not returned, this is a finding.'
  desc 'fix', 'Change the mode of the file "/etc/shadow" to "0000" by running the following command:

$ sudo chmod 0000 /etc/shadow'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61675r925787_chk'
  tag severity: 'medium'
  tag gid: 'V-257934'
  tag rid: 'SV-257934r925789_rule'
  tag stig_id: 'RHEL-09-232270'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61599r925788_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host', 'container'

  system_file = '/etc/shadow'

  mode = input('expected_modes')[system_file]

  describe file(system_file) do
    it { should exist }
    it { should_not be_more_permissive_than(mode) }
  end
end
