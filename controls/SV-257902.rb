control 'SV-257902' do
  title 'RHEL 9 /etc/gshadow file must be owned by root.'
  desc 'The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify the ownership of the "/etc/gshadow" file with the following command:

$ sudo stat -c "%U %n" /etc/gshadow 

root /etc/gshadow 

If "/etc/gshadow" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Change the owner of the file /etc/gshadow to root by running the following command:

$ sudo chown root /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61643r925691_chk'
  tag severity: 'medium'
  tag gid: 'V-257902'
  tag rid: 'SV-257902r925693_rule'
  tag stig_id: 'RHEL-09-232110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61567r925692_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
