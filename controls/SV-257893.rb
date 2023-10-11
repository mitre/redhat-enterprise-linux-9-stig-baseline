control 'SV-257893' do
  title 'RHEL 9 /etc/gshadow file must have mode 0000 or less permissive to prevent unauthorized access.'
  desc 'The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify that the "/etc/gshadow" file has mode "0000" with the following command:

$ sudo stat -c "%a %n" /etc/gshadow

0 /etc/gshadow

If a value of "0" is not returned, this is a finding.'
  desc 'fix', 'Change the mode of the file "/etc/gshadow" to "0000" by running the following command:

$ sudo chmod 0000 /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61634r925664_chk'
  tag severity: 'medium'
  tag gid: 'V-257893'
  tag rid: 'SV-257893r925666_rule'
  tag stig_id: 'RHEL-09-232065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61558r925665_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
