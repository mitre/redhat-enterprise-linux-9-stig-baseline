control 'SV-257861' do
  title 'RHEL 9 must prevent files with the setuid and setgid bit set from being executed on the /boot directory.'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(Note: For systems that use UEFI, this requirement is Not Applicable.

Verify the /boot directory is mounted with the "nosuid" option with the following command:

$ mount | grep '\s/boot\s'

/dev/sda1 on /boot type xfs (rw,nosuid,relatime,seclabe,attr2,inode64,noquota)

If the /boot file system does not have the "nosuid" option set, this is a finding.)
  desc 'fix', 'Modify "/etc/fstab" to use the "nosuid" option on the "/boot" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-257861'
  tag rid: 'SV-257861r925570_rule'
  tag stig_id: 'RHEL-09-231100'
  tag fix_id: 'F-61526r925569_fix'
  tag cci: ['CCI-000366', 'CCI-001764']
  tag nist: ['CM-6 b', 'CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if file('/sys/firmware/efi').exist?
    impact 0.0
    describe 'System running UEFI' do
      skip 'The System is running UEFI, this control is Not Applicable.'
    end
  else
    describe mount('/boot') do
      it { should be_mounted }
      its('options') { should include 'nosuid' }
    end
  end
end
