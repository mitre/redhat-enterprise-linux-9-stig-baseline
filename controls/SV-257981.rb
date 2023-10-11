control 'SV-257981' do
  title 'RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a SSH logon.'
  desc 'The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution.

'
  desc 'check', 'Verify any SSH connection to the operating system displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the system.

Check for the location of the banner file being used with the following command:

$ sudo grep -i banner /etc/ssh/sshd_config

banner /etc/issue

This command will return the banner keyword and the name of the file that contains the SSH banner (in this case "/etc/issue").

If the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via ssh.

Edit the "/etc/ssh/sshd_config" file to uncomment the banner keyword and configure it to point to a file that will contain the logon banner (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).

An example configuration line is:

Banner /etc/issue'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61722r925928_chk'
  tag severity: 'medium'
  tag gid: 'V-257981'
  tag rid: 'SV-257981r925930_rule'
  tag stig_id: 'RHEL-09-255025'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-61646r925929_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
