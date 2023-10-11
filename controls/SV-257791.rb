control 'SV-257791' do
  title 'RHEL 9 /boot/grub2/grub.cfg file must be owned by root.'
  desc 'The " /boot/grub2/grub.cfg" file stores sensitive system configuration. Protection of this file is critical for system security.'
  desc 'check', 'Verify the ownership of the "/boot/grub2/grub.cfg" file with the following command:

$ sudo stat -c "%U %n" /boot/grub2/grub.cfg 

root /boot/grub2/grub.cfg 

If "/boot/grub2/grub.cfg" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Change the owner of the file /boot/grub2/grub.cfg to root by running the following command:

$ sudo chown root /boot/grub2/grub.cfg'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61532r925358_chk'
  tag severity: 'medium'
  tag gid: 'V-257791'
  tag rid: 'SV-257791r925360_rule'
  tag stig_id: 'RHEL-09-212030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61456r925359_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
