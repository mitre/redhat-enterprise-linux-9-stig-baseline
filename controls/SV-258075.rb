control 'SV-258075' do
  title 'RHEL 9 must define default permissions for the system default profile.'
  desc 'The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 600 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.

'
  desc 'check', 'Verify the "umask" setting is configured correctly in the "/etc/profile" file with the following command:

Note: If the value of the "umask" parameter is set to "000" "/etc/profile" file, the Severity is raised to a CAT I.

$ grep umask /etc/profile 

umask 077

If the value for the "umask" parameter is not "077", or the "umask" parameter is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Add or edit the lines for the "umask" parameter in the "/etc/profile" file to "077":

umask 077'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61816r926210_chk'
  tag severity: 'medium'
  tag gid: 'V-258075'
  tag rid: 'SV-258075r926212_rule'
  tag stig_id: 'RHEL-09-412070'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-61740r926211_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00228', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
