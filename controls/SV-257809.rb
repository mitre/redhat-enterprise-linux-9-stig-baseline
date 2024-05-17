control 'SV-257809' do
  title 'RHEL 9 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.'
  desc "Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code they have introduced into a process' address space during an attempt at exploitation. Additionally, ASLR makes it more difficult for an attacker to know the location of existing code in order to repurpose it using return oriented programming (ROP) techniques."
  desc 'check', %q(Verify RHEL 9 is implementing ASLR with the following command:

$ sudo sysctl kernel.randomize_va_space

kernel.randomize_va_space = 2

Check that the configuration files are present to enable this kernel parameter.
Verify the configuration of the kernel.kptr_restrict kernel parameter with the following command:

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' |  grep -F kernel.randomize_va_space | tail -1

kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2" or is missing, this is a finding.)
  desc 'fix', 'Add or edit the following line in a system configuration file in the "/etc/sysctl.d/" directory:

kernel.randomize_va_space = 2

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag gid: 'V-257809'
  tag rid: 'SV-257809r942975_rule'
  tag stig_id: 'RHEL-09-213070'
  tag fix_id: 'F-61474r925413_fix'
  tag cci: ['CCI-002824', 'CCI-000366']
  tag nist: ['SI-16', 'CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  parameter = 'kernel.randomize_va_space'
  value = 2
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  describe kernel_parameter(parameter) do
    its('value') { should eq value }
  end

  search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

  correct_result = search_results.any? { |line| line.match(regexp) }
  incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

  describe 'Kernel config files' do
    it "should configure '#{parameter}'" do
      expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
    end
    unless incorrect_results.nil?
      it 'should not have incorrect or conflicting setting(s) in the config files' do
        expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
      end
    end
  end
end
