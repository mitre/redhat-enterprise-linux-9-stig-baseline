control 'SV-257956' do
  title 'There must be no .shosts files on RHEL 9.'
  desc 'The .shosts files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', 'Verify there are no ".shosts" files on RHEL 9 with the following command:

$ sudo find / -name .shosts

If a ".shosts" file is found, this is a finding.'
  desc 'fix', 'Remove any found ".shosts" files from the system.

$ sudo rm /[path]/[to]/[file]/.shosts'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257956'
  tag rid: 'SV-257956r925855_rule'
  tag stig_id: 'RHEL-09-252075'
  tag fix_id: 'F-61621r925854_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  shosts_files = command('find / -xdev -xautofs -name .shosts').stdout.strip.split("\n")

  describe 'The RHEL8 filesystem' do
    it 'should not have any .shosts files present' do
      expect(shosts_files).to be_empty, "Discovered .shosts files:\n\t- #{shosts_files.join("\n\t- ")}"
    end
  end
end
