control 'SV-257881' do
  title 'RHEL 9 must prevent special devices on non-root local partitions.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', %q(Verify all non-root local partitions are mounted with the "nodev" option
with the following command:

    $ sudo mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev'

    If any output is produced, this is a finding.)
  desc 'fix', 'Configure the "/etc/fstab" to use the "nodev" option on all
non-root local partitions.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257881'
  tag rid: 'SV-257881r991589_rule'
  tag stig_id: 'RHEL-09-231200'
  tag fix_id: 'F-61546r925629_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  option = 'nodev'

  mount_stdout = command('mount').stdout.lines
  failing_mount_points = mount_stdout.select { |mp| mp.match(%r{^/dev\S*\s+on\s+/\S}) }.reject { |mp| mp.match(/\(.*#{option}.*\)/) }

  describe "All mounted devices outside of '/dev' directory" do
    it "should be mounted with the '#{option}' option" do
      expect(failing_mount_points).to be_empty, "Failing devices:\n\t- #{failing_mount_points.join("\n\t- ")}"
    end
  end
end
