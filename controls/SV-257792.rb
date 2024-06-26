control 'SV-257792' do
  title 'RHEL 9 must disable virtual system calls.'
  desc 'System calls are special routines in the Linux kernel, which userspace applications ask to do privileged tasks. Invoking a system call is an expensive operation because the processor must interrupt the currently executing task and switch context to kernel mode and then back to userspace after the system call completes. Virtual system calls map into user space a page that contains some variables and the implementation of some system calls. This allows the system calls to be executed in userspace to alleviate the context switching expense.

Virtual system calls provide an opportunity of attack for a user who has control of the return instruction pointer. Disabling virtual system calls help to prevent return oriented programming (ROP) attacks via buffer overflows and overruns. If the system intends to run containers based on RHEL 6 components, then virtual system calls will need enabled so the components function properly.

'
  desc 'check', %q(Verify the current GRUB 2 configuration disables virtual system calls with the following command:

$ sudo grubby --info=ALL | grep args | grep -v 'vsyscall=none'

If any output is returned, this is a finding.

Check that virtual system calls are disabled by default to persist in kernel updates with the following command:

$ sudo grep vsyscall /etc/default/grub

GRUB_CMDLINE_LINUX="vsyscall=none"

If "vsyscall" is not set to "none", is missing or commented out, and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.)
  desc 'fix', 'Document the use of virtual system calls with the ISSO as an operational requirement or disable them with the following command:

$ sudo grubby --update-kernel=ALL --args="vsyscall=none"

Add or modify the following line in "/etc/default/grub" to ensure the configuration survives kernel updates:

GRUB_CMDLINE_LINUX="vsyscall=none"'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61533r925361_chk'
  tag severity: 'medium'
  tag gid: 'V-257792'
  tag rid: 'SV-257792r925363_rule'
  tag stig_id: 'RHEL-09-212035'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61457r925362_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000134-GPOS-00068']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001084']
  tag nist: ['CM-6 b', 'SC-3']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('vsyscall_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    grub_stdout = command('grubby --info=ALL').stdout
    setting = /vsyscall\s*=\s*none/

    describe 'GRUB config' do
      it 'should disable vsyscall' do
        expect(parse_config(grub_stdout)['args']).to match(setting), 'Current GRUB configuration does not disable this setting'
        expect(parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX']).to match(setting), 'Setting not configured to persist between kernel updates'
      end
    end
  end
end
