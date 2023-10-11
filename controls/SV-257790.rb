control 'SV-257790' do
  title 'RHEL 9 /boot/grub2/grub.cfg file must be group-owned by root.'
  desc 'The "root" group is a highly privileged group. Furthermore, the group-owner of this file should not have any access privileges anyway.'
  desc 'check', 'Verify the group ownership of the "/boot/grub2/grub.cfg" file with the following command:

$ sudo stat -c "%G %n" /boot/grub2/grub.cfg 

root /boot/grub2/grub.cfg

If "/boot/grub2/grub.cfg" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Change the group of the file /boot/grub2/grub.cfg to root by running the following command:

$ sudo chgrp root /boot/grub2/grub.cfg'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61531r925355_chk'
  tag severity: 'medium'
  tag gid: 'V-257790'
  tag rid: 'SV-257790r925357_rule'
  tag stig_id: 'RHEL-09-212025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61455r925356_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
