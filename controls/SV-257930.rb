control 'SV-257930' do
  title 'All RHEL 9 local files and directories must have a valid group owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if
a group is assigned the same Group Identifier (GID) as the GID of the files
without a valid group owner.'
  desc 'check', "Verify all local files and directories on RHEL 9 have a valid group with the following command:

$ df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nogroup

If any files on the system do not have an assigned group, this is a finding."
  desc 'fix', 'Either remove all files and directories from RHEL 9 that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command:

$ sudo chgrp <group> <file>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257930'
  tag rid: 'SV-257930r925777_rule'
  tag stig_id: 'RHEL-09-232250'
  tag fix_id: 'F-61595r925776_fix'
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
      failing_files += command("find / -xdev -xautofs -fstype #{fs} -nogroup").stdout.strip.split("\n")
    end

    describe 'All files on RHEL 9' do
      it 'should have a group' do
        expect(failing_files).to be_empty, "Files with no group:\n\t- #{failing_files.join("\n\t- ")}"
      end
    end
  end
end
