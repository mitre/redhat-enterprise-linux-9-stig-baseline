control 'SV-257894' do
  title 'RHEL 9 /etc/gshadow- file must have mode 0000 or less permissive to prevent unauthorized access.'
  desc 'The "/etc/gshadow-" file is a backup of "/etc/gshadow", and as such, contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify that the "/etc/gshadow-" file has mode "0000" with the following command:

$ sudo stat -c "%a %n" /etc/gshadow-

0 /etc/gshadow-

If a value of "0" is not returned, this is a finding.'
  desc 'fix', 'Change the mode of the file "/etc/gshadow-" to "0000" by running the following command:

$ sudo chmod 0000 /etc/gshadow-'
  impact 0.5
  tag check_id: 'C-61635r925667_chk'
  tag severity: 'medium'
  tag gid: 'V-257894'
  tag rid: 'SV-257894r991589_rule'
  tag stig_id: 'RHEL-09-232070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61559r925668_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
