control 'SV-257860' do
  title 'RHEL 9 must mount /boot with the nodev option.'
  desc 'The only legitimate location for device files is the "/dev" directory located on the root partition. The only exception to this is chroot jails.'
  desc 'check', %q(Verify that the "/boot" mount point has the "nodev" option with the following command:

$ mount | grep '\s/boot\s'

/dev/sda1 on /boot type xfs (rw,nodev,relatime,seclabel,attr2)

If the "/boot" file system does not have the "nodev" option set, this is a finding.)
  desc 'fix', 'Modify "/etc/fstab" to use the "nodev" option on the "/boot" directory.'
  impact 0.5
  tag check_id: 'C-61601r1044939_chk'
  tag severity: 'medium'
  tag gid: 'V-257860'
  tag rid: 'SV-257860r1044940_rule'
  tag stig_id: 'RHEL-09-231095'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-61525r925566_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  directory = '/boot'
  parameter = 'nodev'

  if file('/sys/firmware/efi').exist?
    impact 0.0
    describe 'System running UEFI' do
      skip 'The System is running UEFI, this control is Not Applicable.'
    end
  else
    describe mount(directory) do
      it { should be_mounted }
      its('options') { should include parameter }
    end
  end
end
