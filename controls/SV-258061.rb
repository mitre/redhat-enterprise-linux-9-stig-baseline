control 'SV-258061' do
  title 'RHEL 9 groups must have unique Group ID (GID).'
  desc 'To ensure accountability and prevent unauthenticated access, groups must be identified uniquely to prevent potential misuse and compromise of the system.'
  desc 'check', 'Verify that RHEL 9 contains no duplicate GIDs for interactive users with the following command:
 
 $  cut -d : -f 3 /etc/group | uniq -d
 
If the system has duplicate GIDs, this is a finding.'
  desc 'fix', 'Edit the file "/etc/group" and provide each group that has a duplicate GID with a unique GID.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61802r926168_chk'
  tag severity: 'medium'
  tag gid: 'V-258061'
  tag rid: 'SV-258061r926170_rule'
  tag stig_id: 'RHEL-09-411110'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-61726r926169_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
