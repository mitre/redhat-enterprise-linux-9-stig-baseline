control 'SV-257848' do
  title 'RHEL 9 must use a separate file system for /var/tmp.'
  desc 'The "/var/tmp" partition is used as temporary storage by many programs. Placing "/var/tmp" in its own partition enables the setting of more restrictive mount options, which can help protect programs that use it.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/var/tmp" with the following command:

$ mount | grep /var/tmp

UUID=c274f65f-c5b5-4379-b017-bee96feb7a34 /var/log xfs noatime 1 2

If a separate entry for "/var/tmp" is not in use, this is a finding.'
  desc 'fix', 'Migrate the "/var/tmp" path onto a separate file system.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257848'
  tag rid: 'SV-257848r925531_rule'
  tag stig_id: 'RHEL-09-231035'
  tag fix_id: 'F-61513r925530_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe mount('/var/tmp') do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == '/var/tmp' } do
    it { should exist }
  end
end
