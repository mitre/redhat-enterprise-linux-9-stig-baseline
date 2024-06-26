control 'SV-257844' do
  title 'RHEL 9 must use a separate file system for /tmp.'
  desc 'The "/tmp" partition is used as temporary storage by many programs. Placing "/tmp" in its own partition enables the setting of more restrictive mount options, which can help protect programs that use it.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/tmp" with the following command:

$ mount | grep /tmp

tmpfs /tmp tmpfs noatime,mode=1777 0 0

If a separate entry for "/tmp" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/tmp" path onto a separate file system.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257844'
  tag rid: 'SV-257844r925519_rule'
  tag stig_id: 'RHEL-09-231015'
  tag fix_id: 'F-61509r925518_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe mount('/tmp') do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == '/tmp' } do
    it { should exist }
  end
end
