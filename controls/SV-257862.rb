control 'SV-257862' do
  title 'RHEL 9 must prevent files with the setuid and setgid bit set from being executed on the /boot/efi directory.'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(Note: For systems that use BIOS, this requirement is Not Applicable.

Verify the /boot/efi directory is mounted with the "nosuid" option with the following command:

$ mount | grep '\s/boot/efi\s'

/dev/sda1 on /boot/efi type vfat (rw,nosuid,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=winnt,errors=remount-ro)

If the /boot/efi file system does not have the "nosuid" option set, this is a finding.)
  desc 'fix', 'Modify "/etc/fstab" to use the "nosuid" option on the "/boot/efi" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-257862'
  tag rid: 'SV-257862r925573_rule'
  tag stig_id: 'RHEL-09-231105'
  tag fix_id: 'F-61527r925572_fix'
  tag cci: ['CCI-000366', 'CCI-001764']
  tag nist: ['CM-6 b', 'CM-7 (2)']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if file('/sys/firmware/efi').exist?
    describe mount('/boot/efi') do
      it { should be_mounted }
      its('options') { should include 'nosuid' }
    end
  else
    impact 0.0
    describe 'System running BIOS' do
      skip 'The System is running a BIOS, this control is Not Applicable.'
    end
  end
end
