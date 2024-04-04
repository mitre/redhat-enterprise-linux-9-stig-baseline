control 'SV-257795' do
  title 'RHEL 8 must enable mitigations against processor-based
vulnerabilities.'
  desc 'It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Operating systems are capable of providing a wide variety of functions and
services. Some of the functions and services, provided by default, may not be
necessary to support essential organizational operations (e.g., key missions,
functions).

    Examples of non-essential capabilities include, but are not limited to,
games, software packages, tools, and demonstration software not related to
requirements or providing a wide array of functionality not required for every
mission, but which cannot be disabled.

    Verify the operating system is configured to disable non-essential
capabilities. The most secure way of ensuring a non-essential capability is
disabled is to not have the capability installed.

    Kernel page-table isolation is a kernel feature that mitigates the Meltdown
security vulnerability and hardens the kernel against attempts to bypass kernel
address space layout randomization (KASLR).'
  desc 'check', 'Verify RHEL 8 enables kernel page-table isolation with the following commands:

$ sudo grub2-editenv list | grep pti

kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet fips=1 audit=1 audit_backlog_limit=8192 pti=on boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

If the "pti" entry does not equal "on", is missing, or the line is commented out, this is a finding.

Check that kernel page-table isolation is enabled by default to persist in kernel updates:

$ sudo grep pti /etc/default/grub

GRUB_CMDLINE_LINUX="pti=on"

If "pti" is not set to "on", is missing or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to enable kernel page-table isolation with the following
command:

    $ sudo grubby --update-kernel=ALL --args="pti=on"

    Add or modify the following line in "/etc/default/grub" to ensure the
configuration survives kernel updates:

    GRUB_CMDLINE_LINUX="pti=on"'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-230491'
  tag rid: 'SV-257795r818842_rule'
  tag stig_id: 'RHEL-08-040004'
  tag fix_id: 'F-33135r568220_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  grub_stdout = command('grub2-editenv - list').stdout

  describe parse_config(grub_stdout) do
    its('kernelopts') { should match(/pti=on/) }
  end
  describe parse_config_file('/etc/default/grub') do
    its('GRUB_CMDLINE_LINUX') { should match(/pti=on/) }
  end
end
