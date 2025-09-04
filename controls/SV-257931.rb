control 'SV-257931' do
  title 'All RHEL 9 local files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same user identifier "UID" as the UID of the unowned files.'
  desc 'check', "Verify all local files and directories on RHEL 9 have a valid owner with the following command:

$ df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nouser

If any files on the system do not have an assigned owner, this is a finding."
  desc 'fix', 'Either remove all files and directories from the system that do not have a valid user, or assign a valid user to all unowned files and directories on RHEL 9 with the "chown" command:

$ sudo chown <user> <file>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257931'
  tag rid: 'SV-257931r925780_rule'
  tag stig_id: 'RHEL-09-232255'
  tag fix_id: 'F-61596r925779_fix'
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

    describe 'All files on RHEL 9' do
      it 'should have an owner' do
        expect(failing_files).to be_empty, "Files with no owner:\n\t- #{failing_files.join("\n\t- ")}"
      end
    end
  end
end
