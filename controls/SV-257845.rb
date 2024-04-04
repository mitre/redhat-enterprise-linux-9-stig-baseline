control 'SV-257845' do
  title 'RHEL 8 must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the
system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system has been created for "/var".

Check that a file system has been created for "/var" with the following command:

     $ sudo grep /var /etc/fstab

     /dev/mapper/...   /var   xfs   defaults,nodev 0 0

If a separate entry for "/var" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var" path onto a separate file system.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230292'
  tag rid: 'SV-257845r902718_rule'
  tag stig_id: 'RHEL-08-010540'
  tag fix_id: 'F-32936r567623_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe mount('/var') do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == '/var' } do
    it { should exist }
  end
end
