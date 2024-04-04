control 'SV-257929' do
  title 'A sticky bit must be set on all RHEL 8 public directories to prevent
unauthorized and unintended information transferred via shared system
resources.'
  desc 'Preventing unauthorized information transfers mitigates the risk of
information, including encrypted representations of information, produced by
the actions of prior users/roles (or the actions of processes acting on behalf
of prior users/roles) from being available to any current users/roles (or
current processes) that obtain access to shared system resources (e.g.,
registers, main memory, hard disks) after those resources have been released
back to information systems. The control of information in shared resources is
also commonly referred to as object reuse and residual information protection.

    This requirement generally applies to the design of an information
technology product, but it can also apply to the configuration of particular
information system components that are, or use, such products. This can be
verified by acceptance/validation processes in DoD or other government agencies.

    There may be shared resources with configurable protections (e.g., files in
storage) that may be assessed on specific information system components.'
  desc 'check', 'Verify that all world-writable directories have the sticky bit set.

Check to see that all world-writable directories have the sticky bit set by running the following command:

$ sudo find / -type d \\( -perm -0002 -a ! -perm -1000 \\) -print 2>/dev/null

drwxrwxrwt 7 root root 4096 Jul 26 11:19 /tmp

If any of the returned directories are world-writable and do not have the sticky bit set, this is a finding.'
  desc 'fix', 'Configure all world-writable directories to have the sticky bit set to
prevent unauthorized and unintended information transferred via shared system
resources.

    Set the sticky bit on all world-writable directories using the command,
replace "[World-Writable Directory]" with any directory path missing the
sticky bit:

    $ sudo chmod 1777 [World-Writable Directory]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag gid: 'V-230243'
  tag rid: 'SV-257929r792857_rule'
  tag stig_id: 'RHEL-08-010190'
  tag fix_id: 'F-32887r567476_fix'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
  tag 'host'
  tag 'container'

  partitions = etc_fstab.params.map { |partition| partition['mount_point'] }.uniq

  ww_dirs = command("find #{partitions} -type d \\( -perm -0002 -a ! -perm -1000 \\) -print 2>/dev/null").stdout.split("\n")

  if ww_dirs.empty?
    describe 'List of world-writable directories on the target' do
      subject { ww_dirs }
      it { should be_empty }
    end
  else
    non_sticky_ww_dirs = ww_dirs.reject { |dir| file(dir).sticky? }
    describe 'All world-writeable directories' do
      it 'should have the sticky bit set' do
        fail_msg = "Public directories without sticky bit:\n\t- #{non_sticky_ww_dirs.join("\n\t- ")}"
        expect(non_sticky_ww_dirs).to be_empty, fail_msg
      end
    end
  end
end
