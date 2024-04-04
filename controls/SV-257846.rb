control 'SV-257846' do
  title 'RHEL 8 must use a separate file system for /var/log.'
  desc 'The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system has been created for "/var/log".

Check that a file system has been created for "/var/log" with the following command:

     $ sudo grep /var/log /etc/fstab

     /dev/mapper/...   /var/log   xfs   defaults,nodev,noexec,nosuid 0 0

If a separate entry for "/var/log" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var/log" path onto a separate file system.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230293'
  tag rid: 'SV-257846r902720_rule'
  tag stig_id: 'RHEL-08-010541'
  tag fix_id: 'F-32937r567626_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe mount('/var/log') do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == '/var/log' } do
    it { should exist }
  end
end
