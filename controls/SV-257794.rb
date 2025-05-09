control 'SV-257794' do
  title 'RHEL 9 must clear memory when it is freed to prevent use-after-free attacks.'
  desc 'Some adversaries launch attacks with the intent of executing code in nonexecutable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be either hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Poisoning writes an arbitrary value to freed pages, so any modification or reference to that page after being freed or before being initialized will be detected and prevented. This prevents many types of use-after-free vulnerabilities at little performance cost. Also prevents leak of data and detection of corrupted memory.

init_on_free is a Linux kernel boot parameter that enhances security by initializing memory regions when they are freed, preventing data leakage. This process ensures that stale data in freed memory cannot be accessed by malicious programs.

SLUB canaries add a randomized value (canary) at the end of SLUB-allocated objects to detect memory corruption caused by buffer overflows or underflows. Redzoning adds padding (red zones) around SLUB-allocated objects to detect overflows or underflows by triggering a fault when adjacent memory is accessed. SLUB canaries are often more efficient and provide stronger detection against buffer overflows compared to redzoning. SLUB canaries are supported in hardened Linux kernels like the ones provided by Linux-hardened.

SLAB objects are blocks of physically contiguous memory. SLUB is the unqueued SLAB allocator.'
  desc 'check', 'Verify that GRUB2 is configured to mitigate use-after-free vulnerabilities by employing memory poisoning.

Inspect the "GRUB_CMDLINE_LINUX" entry of /etc/default/grub as follows:
$ sudo grep -i grub_cmdline_linux /etc/default/grub
GRUB_CMDLINE_LINUX="... init_on_free=1"

If "init_on_free=1" is missing or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to enable init_on_free with the following command:
$ sudo grubby --update-kernel=ALL --args="init_on_free=1"

Regenerate the GRUB configuration:
$ sudo grub2-mkconfig -o /boot/grub2/grub.cfg

Reboot the system:
$ sudo reboot'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag satisfies: ['SRG-OS-000134-GPOS-00068', 'SRG-OS-000433-GPOS-00192']
  tag gid: 'V-257794'
  tag rid: 'SV-257794r1069362_rule'
  tag stig_id: 'RHEL-09-212045'
  tag fix_id: 'F-61459r1069361_fix'
  tag cci: ['CCI-001084', 'CCI-002824']
  tag nist: ['SC-3', 'SI-16']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  grub_stdout = command('grubby --info=ALL').stdout
  setting = /slub_debug\s*=\s*P/

  describe 'GRUB config' do
    it 'should enable page poisoning' do
      expect(parse_config(grub_stdout)['args']).to match(setting), 'Current GRUB configuration does not disable this setting'
      expect(parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX']).to match(setting), 'Setting not configured to persist between kernel updates'
    end
  end
end
