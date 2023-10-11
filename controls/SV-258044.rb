control 'SV-258044' do
  title 'RHEL 9 must set the umask value to 077 for all local interactive user accounts.'
  desc 'The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 600 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.'
  desc 'check', 'Verify that the default umask for all local interactive users is "077".

Identify the locations of all local interactive user home directories by looking at the "/etc/passwd" file.

Check all local interactive user initialization files for interactive users with the following command:

Note: The example is for a system that is configured to create users home directories in the "/home" directory.

# grep -ri umask /home/

/home/wadea/.bash_history:grep -i umask /etc/bashrc /etc/csh.cshrc /etc/profile
/home/wadea/.bash_history:grep -i umask /etc/login.defs

If any local interactive user initialization files are found to have a umask statement that sets a value less restrictive than "077", this is a finding.'
  desc 'fix', %q(Remove the umask statement from all local interactive user's initialization files. 

If the account is for an application, the requirement for a umask less restrictive than "077" can be documented with the information system security officer, but the user agreement for access to the account must specify that the local interactive user must log on to their account first and then switch the user to the application account with the correct option to gain the account's environment variables.)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61785r926117_chk'
  tag severity: 'medium'
  tag gid: 'V-258044'
  tag rid: 'SV-258044r926119_rule'
  tag stig_id: 'RHEL-09-411025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61709r926118_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
