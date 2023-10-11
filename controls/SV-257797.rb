control 'SV-257797' do
  title 'RHEL 9 must restrict access to the kernel message buffer.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DOD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

Restricting access to the kernel message buffer limits access to only root. This prevents attackers from gaining additional system information as a nonprivileged user.

'
  desc 'check', %q(Verify RHEL 9 is configured to restrict access to the kernel message buffer with the following commands:

Check the status of the kernel.dmesg_restrict kernel parameter.

$ sysctl kernel.dmesg_restrict

kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F kernel.dmesg_restrict | tail -1

kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to restrict access to the kernel message buffer.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.dmesg_restrict = 1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61538r925376_chk'
  tag severity: 'medium'
  tag gid: 'V-257797'
  tag rid: 'SV-257797r925378_rule'
  tag stig_id: 'RHEL-09-213010'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-61462r925377_fix'
  tag satisfies: ['SRG-OS-000132-GPOS-00067', 'SRG-OS-000138-GPOS-00069']
  tag 'documentable'
  tag cci: ['CCI-001082', 'CCI-001090']
  tag nist: ['SC-2', 'SC-4']
end
