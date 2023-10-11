control 'SV-257881' do
  title 'RHEL 9 must prevent special devices on non-root local partitions.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', %q(Verify all non-root local partitions are mounted with the "nodev" option with the following command:

$ sudo mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev'

If any output is produced, this is a finding.)
  desc 'fix', 'Configure the "/etc/fstab" to use the "nodev" option on all non-root local partitions.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61622r925628_chk'
  tag severity: 'medium'
  tag gid: 'V-257881'
  tag rid: 'SV-257881r925630_rule'
  tag stig_id: 'RHEL-09-231200'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61546r925629_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
