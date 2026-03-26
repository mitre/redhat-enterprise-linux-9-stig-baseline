control 'SV-257905' do
  title 'RHEL 9 /etc/gshadow- file must be group-owned by root.'
  desc 'The "/etc/gshadow-" file is a backup of "/etc/gshadow", and as such, contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify the group ownership of the "/etc/gshadow-" file with the following command:

$ sudo stat -c "%G %n" /etc/gshadow- 

root /etc/gshadow-

If "/etc/gshadow-" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Change the group of the file /etc/gshadow- to root by running the following command:

$ sudo chgrp root /etc/gshadow-'
  impact 0.5
  tag check_id: 'C-61646r925700_chk'
  tag severity: 'medium'
  tag gid: 'V-257905'
  tag rid: 'SV-257905r991589_rule'
  tag stig_id: 'RHEL-09-232125'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61570r925701_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
