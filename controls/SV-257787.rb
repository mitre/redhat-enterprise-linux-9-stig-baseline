control 'SV-257787' do
  title 'RHEL 9 must require a boot loader superuser password.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DOD-approved PKIs, all DOD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Password protection on the boot loader configuration ensures users with physical access cannot trivially alter important bootloader settings. These include which kernel to use, and whether to enter single-user mode.'
  desc 'check', 'Verify the boot loader superuser password has been set and run the following command:

$ sudo grep "superusers" /etc/grub2.cfg

password_pbkdf2  superusers-account   ${GRUB2_PASSWORD}

To verify the boot loader superuser account password has been set, and the password encrypted, run the following command:

$ sudo cat /boot/grub2/user.cfg

GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.C4E08AC72FBFF7E837FD267BFAD7AEB3D42DDC
2C99F2A94DD5E2E75C2DC331B719FE55D9411745F82D1B6CFD9E927D61925F9BBDD1CFAA0080E0
916F7AB46E0D.1302284FCCC52CD73BA3671C6C12C26FF50BA873293B24EE2A96EE3B57963E6D7
0C83964B473EC8F93B07FE749AA6710269E904A9B08A6BBACB00A2D242AD828

If a "GRUB2_PASSWORD" is not set, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to require a grub bootloader password for the grub superuser account.

Generate an encrypted grub2 password for the grub superuser account with the following command:

$ sudo grub2-setpassword
Enter password:
Confirm password:'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61528r925346_chk'
  tag severity: 'medium'
  tag gid: 'V-257787'
  tag rid: 'SV-257787r925348_rule'
  tag stig_id: 'RHEL-09-212010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-61452r925347_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  grubfile = input('grub_conf_path')
  grub_userfile = input('grub_user_conf_path')

  describe file(grubfile) do
    it { should exist }
  end

  describe file(grub_userfile) do
    it { should exist }
  end

  if file(grubfile).exist? && file(grub_userfile).exist?
    password_set = file(grubfile).content.lines.select { |line| line.match(/password_pbkdf2\s+\w+\s+\$\{\w+\}/) }

    describe 'The GRUB bootloader superuser password' do
      it "should be set in the GRUB config file (\'#{grubfile}\')" do
        expect(password_set).to_not be_empty, "No bootloader superuser password set in \'#{grubfile}\'"
      end

      grub_envar = password_set.first.match(/\$\{(?<grub_pw_envar>\w+)\}/).captures.first
      password_encrypted = file(grub_userfile).content.match?(/#{grub_envar}=grub.pbkdf2/)
      it "should be encrypted in the user config file (\'#{grub_userfile}\')" do
        expect(password_encrypted).to eq(true), "GRUB password environment variable not set to an encrypted value in \'#{grub_userfile}\'"
      end
    end
  end
end
