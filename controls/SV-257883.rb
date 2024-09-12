control 'SV-257883' do
  title 'RHEL 9 library directories must have mode 755 or less permissive.'
  desc 'If RHEL 9 allowed any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 9 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify the system-wide shared library directories have mode "755" or less permissive with the following command:

$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type d -exec ls -l {} \\;

If any system-wide shared library file is found to be group-writable or world-writable, this is a finding.'
  desc 'fix', 'Configure the system-wide shared library directories (/lib, /lib64, /usr/lib and /usr/lib64) to be protected from unauthorized access.

Run the following command, replacing "[DIRECTORY]" with any library directory with a mode more permissive than 755.

$ sudo chmod 755 [DIRECTORY]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-257883'
  tag rid: 'SV-257883r991560_rule'
  tag stig_id: 'RHEL-09-232015'
  tag fix_id: 'F-61548r925635_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  mode_for_libs = input('mode_for_libs')

  overly_permissive_libs = input('system_libraries').select { |lib|
    file(lib).more_permissive_than?(mode_for_libs)
  }

  describe 'System libraries' do
    it "should not have modes set higher than #{mode_for_libs}" do
      fail_msg = "Overly permissive system libraries:\n\t- #{overly_permissive_libs.join("\n\t- ")}"
      expect(overly_permissive_libs).to be_empty, fail_msg
    end
  end
end
