control 'SV-257931' do
  title 'All RHEL 8 local files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a
user is assigned the same User Identifier "UID" as the UID of the un-owned
files.'
  desc 'check', 'Verify all local files and directories on RHEL 8 have a valid owner with
the following command:

    Note: The value after -fstype must be replaced with the filesystem type.
XFS is used as an example.

    $ sudo find / -fstype xfs -nouser

    If any files on the system do not have an assigned owner, this is a finding.

    Note: Command may produce error messages from the /proc and /sys
directories.'
  desc 'fix', 'Either remove all files and directories from the system that do not have a
valid user, or assign a valid user to all unowned files and directories on RHEL
8 with the "chown" command:

    $ sudo chown <user> <file>'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230326'
  tag rid: 'SV-257931r627750_rule'
  tag stig_id: 'RHEL-08-010780'
  tag fix_id: 'F-32970r567725_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  if input('disable_slow_controls')
    describe 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute.' do
      skip 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute. You must enable this control for a full accredidation for production.'
    end
  else

    failing_files = Set[]

    command('grep -v "nodev" /proc/filesystems | awk \'NF{ print $NF }\'')
      .stdout.strip.split("\n").each do |fs|
      failing_files += command("find / -xdev -xautofs -fstype #{fs} -nouser").stdout.strip.split("\n")
    end

    describe 'All files on RHEL 8' do
      it 'should have an owner' do
        expect(failing_files).to be_empty, "Files with no owner:\n\t- #{failing_files.join("\n\t- ")}"
      end
    end
  end
end
