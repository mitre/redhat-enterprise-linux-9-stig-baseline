control 'SV-257816' do
  title 'RHEL 9 must disable the use of user namespaces.'
  desc 'User namespaces are used primarily for Linux containers. The value "0" disallows the use of user namespaces.'
  desc 'check', %q(Verify RHEL 9 disables the use of user namespaces with the following commands:

Note: User namespaces are used primarily for Linux containers. If containers are in use, this requirement is Not Applicable.

$ sysctl user.max_user_namespaces

user.max_user_namespaces = 0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F user.max_user_namespaces | tail -1
user.max_user_namespaces = 0

If the network parameter "user.max_user_namespaces" is not equal to "0", or nothing is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to disable the use of user namespaces by adding the following line to a file, in the "/etc/sysctl.d" directory:

Note: User namespaces are used primarily for Linux containers. If containers are in use, this requirement is Not Applicable. 

user.max_user_namespaces = 0

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61557r925433_chk'
  tag severity: 'medium'
  tag gid: 'V-257816'
  tag rid: 'SV-257816r925435_rule'
  tag stig_id: 'RHEL-09-213105'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61481r925434_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
