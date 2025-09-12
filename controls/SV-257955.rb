control 'SV-257955' do
  title 'There must be no shosts.equiv files on RHEL 9.'
  desc 'The shosts.equiv files are used to configure host-based authentication for the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', 'Verify there are no "shosts.equiv" files on RHEL 9 with the following command:

$ sudo find / -name shosts.equiv

If a "shosts.equiv" file is found, this is a finding.'
  desc 'fix', 'Remove any found "shosts.equiv" files from the system.

$ sudo rm /[path]/[to]/[file]/shosts.equiv'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-257955'
  tag rid: 'SV-257955r991589_rule'
  tag stig_id: 'RHEL-09-252070'
  tag fix_id: 'F-61620r925851_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  shosts_files = command('find / -xdev -xautofs -name shosts.equiv').stdout.strip.split("\n")

  describe 'The filesystem' do
    it 'should not have any shosts.equiv files present' do
      expect(shosts_files).to be_empty, "Discovered shosts files:\n\t- #{shosts_files.join("\n\t- ")}"
    end
  end
end
