control 'SV-257895' do
  title 'RHEL 9 /etc/passwd file must have mode 0644 or less permissive to prevent unauthorized access.'
  desc 'If the "/etc/passwd" file is writable by a group-owner or the world the risk of its compromise is increased. The file contains the list of accounts on the system and associated information, and protection of this file is critical for system security.'
  desc 'check', 'Verify that the "/etc/passwd" file has mode "0644" or less permissive with the following command:

$ sudo stat -c "%a %n" /etc/passwd

644 /etc/passwd

If a value of "0644" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Change the mode of the file "/etc/passwd" to "0644" by running the following command:

$ sudo chmod 0644 /etc/passwd'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61636r925670_chk'
  tag severity: 'medium'
  tag gid: 'V-257895'
  tag rid: 'SV-257895r925672_rule'
  tag stig_id: 'RHEL-09-232075'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61560r925671_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
