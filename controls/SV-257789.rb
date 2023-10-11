control 'SV-257789' do
  title 'RHEL 9 must require a unique superusers name upon booting into single-user and maintenance modes.'
  desc 'Having a nondefault grub superuser username makes password-guessing attacks less effective.'
  desc 'check', 'Verify the boot loader superuser account has been set with the following command:

$ sudo grep -A1 "superusers" /etc/grub2.cfg 

 set superusers="<superusers-account>"
export superusers
 
The <superusers-account> is the actual account name different from common names like root, admin, or administrator.

If superusers contains easily guessable usernames, this is a finding.'
  desc 'fix', %q(Configure RHEL 9 to have a unique username for the grub superuser account.

Edit the "/etc/grub.d/01_users" file and add or modify the following lines in the "### BEGIN /etc/grub.d/01_users ###" section:

set superusers="superusers-account"
export superusers

Once the superuser account has been added, update the grub.cfg file by running:

$ sudo grubby --update-kernel=ALL')
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61530r925352_chk'
  tag severity: 'high'
  tag gid: 'V-257789'
  tag rid: 'SV-257789r925354_rule'
  tag stig_id: 'RHEL-09-212020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-61454r925353_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
