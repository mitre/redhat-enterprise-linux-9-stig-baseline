control 'SV-257910' do
  title 'RHEL 9 /etc/shadow file must be owned by root.'
  desc 'The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information, which could weaken the system security posture.'
  desc 'check', 'Verify the ownership of the "/etc/shadow" file with the following command:

$ sudo stat -c "%U %n" /etc/shadow

root /etc/shadow

If "/etc/shadow" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Change the owner of the file /etc/shadow to root by running the following command:

$ sudo chown root /etc/shadow'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61651r925715_chk'
  tag severity: 'medium'
  tag gid: 'V-257910'
  tag rid: 'SV-257910r925717_rule'
  tag stig_id: 'RHEL-09-232150'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61575r925716_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
