control 'SV-258074' do
  title 'RHEL 9 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.'
  desc 'check', 'Verify RHEL 9 defines default permissions for all authenticated users in such a way that the user can only read and modify their own files with the following command:

Note: If the value of the "UMASK" parameter is set to "000" in "/etc/login.defs" file, the Severity is raised to a CAT I.

# grep -i umask /etc/login.defs

UMASK 077

If the value for the "UMASK" parameter is not "077", or the "UMASK" parameter is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Add or edit the lines for the "UMASK" parameter in the "/etc/login.defs" file to "077":

UMASK 077'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61815r926207_chk'
  tag severity: 'medium'
  tag gid: 'V-258074'
  tag rid: 'SV-258074r926209_rule'
  tag stig_id: 'RHEL-09-412065'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-61739r926208_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
