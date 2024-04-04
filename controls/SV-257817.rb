control 'SV-257817' do
  title 'RHEL 8 must implement non-executable data to protect its memory from
unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can be either hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the NX (no-execution) bit flag is set on the system.

    Check that the no-execution bit flag is set with the following commands:

    $ sudo dmesg | grep NX

    [ 0.000000] NX (Execute Disable) protection: active

    If "dmesg" does not show "NX (Execute Disable) protection" active,
check the cpuinfo settings with the following command:

    $ sudo less /proc/cpuinfo | grep -i flags
    flags : fpu vme de pse tsc ms nx rdtscp lm constant_tsc

    If "flags" does not contain the "nx" flag, this is a finding.'
  desc 'fix', 'The NX bit execute protection must be enabled in the system
BIOS.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag gid: 'V-230276'
  tag rid: 'SV-257817r854031_rule'
  tag stig_id: 'RHEL-08-010420'
  tag fix_id: 'F-32920r567575_fix'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  options = {
    assignment_regex: /^\s*([^:]*?)\s*:\s*(.*?)\s*$/
  }

  dmesg_nx_conf = command('dmesg | grep NX').stdout.match(/:\s+(\S+)$/).captures.first
  cpuinfo_flags = parse_config_file('/proc/cpuinfo', options).flags.split

  describe.one do
    describe 'The no-execution bit flag' do
      it 'should be set in kernel messages' do
        expect(dmesg_nx_conf).to eq('active'), "dmesg does not show NX protection set to 'active'"
      end
    end
    describe 'The no-execution bit flag' do
      it 'should be set in CPU info' do
        expect(cpuinfo_flags).to include('nx'), "'nx' flag not set in /proc/cpuinfo flags"
      end
    end
  end
end
