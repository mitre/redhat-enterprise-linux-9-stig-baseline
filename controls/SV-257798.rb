control 'SV-257798' do
  title 'RHEL 9 must prevent kernel profiling by nonprivileged users.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DOD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

Setting the kernel.perf_event_paranoid kernel parameter to "2" prevents attackers from gaining additional system information as a nonprivileged user.

'
  desc 'check', %q(Verify RHEL 9 is configured to prevent kernel profiling by nonprivileged users with the following commands:

Check the status of the kernel.perf_event_paranoid kernel parameter.

$sysctl kernel.perf_event_paranoid

kernel.perf_event_paranoid = 2

If "kernel.perf_event_paranoid" is not set to "2" or is missing, this is a finding.
Check that the configuration files are present to enable this kernel parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config  | egrep -v '^(#|;)' | grep -F kernel.perf_event_paranoid | tail -1

kernel.perf_event_paranoid = 2

If "kernel.perf_event_paranoid" is not set to "2" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to prevent kernel profiling by nonprivileged users.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.perf_event_paranoid = 2

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61539r925379_chk'
  tag severity: 'medium'
  tag gid: 'V-257798'
  tag rid: 'SV-257798r925381_rule'
  tag stig_id: 'RHEL-09-213015'
  tag gtitle: 'SRG-OS-000132-GPOS-00067'
  tag fix_id: 'F-61463r925380_fix'
  tag satisfies: ['SRG-OS-000132-GPOS-00067', 'SRG-OS-000138-GPOS-00069']
  tag 'documentable'
  tag cci: ['CCI-001082', 'CCI-001090']
  tag nist: ['SC-2', 'SC-4']
end
