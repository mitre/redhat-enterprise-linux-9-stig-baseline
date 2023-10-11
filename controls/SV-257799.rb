control 'SV-257799' do
  title 'RHEL 9 must prevent the loading of a new kernel for later execution.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Disabling kexec_load prevents an unsigned kernel image (that could be a windows kernel or modified vulnerable kernel) from being loaded. Kexec can be used subvert the entire secureboot process and should be avoided at all costs especially since it can load unsigned kernel images.

'
  desc 'check', %q(Verify RHEL 9 is configured to disable kernel image loading.

Check the status of the kernel.kexec_load_disabled kernel parameter with the following command:

$ sysctl kernel.kexec_load_disabled

kernel.kexec_load_disabled = 1

If "kernel.kexec_load_disabled" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter with the following command:

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F kernel.kexec_load_disabled | tail -1

kernel.kexec_load_disabled = 1

If "kernel.kexec_load_disabled" is not set to "1" or is missing, this is a finding.)
  desc 'fix', 'Add or edit the following line in a system configuration file in the "/etc/sysctl.d/" directory:

kernel.kexec_load_disabled = 1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61540r925382_chk'
  tag severity: 'medium'
  tag gid: 'V-257799'
  tag rid: 'SV-257799r925384_rule'
  tag stig_id: 'RHEL-09-213020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61464r925383_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000366-GPOS-00153']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001749']
  tag nist: ['CM-6 b', 'CM-5 (3)']
end
