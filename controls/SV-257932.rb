control 'SV-257932' do
  title 'RHEL 9 must be configured so that all system device files are correctly labeled to prevent unauthorized modification.'
  desc 'If an unauthorized or modified device is allowed to exist on the system, there is the possibility the system may perform unintended or unauthorized operations.'
  desc 'check', 'Verify that all system device files are correctly labeled to prevent unauthorized modification.

List all device files on the system that are incorrectly labeled with the following commands:

Note: Device files are normally found under "/dev", but applications may place device files in other directories and may necessitate a search of the entire system.

# find /dev -context *:device_t:* \\( -type c -o -type b \\) -printf "%p %Z\\n"

# find /dev -context *:unlabeled_t:* \\( -type c -o -type b \\) -printf "%p %Z\\n"

Note: There are device files, such as "/dev/vmci", that are used when the operating system is a host virtual machine. They will not be owned by a user on the system and require the "device_t" label to operate. These device files are not a finding.

If there is output from either of these commands, other than already noted, this is a finding.'
  desc 'fix', 'Restore the SELinux policy for the affected device file from the system policy database using the following command:

$ sudo restorecon -v <device_path>

Substituting "<device_path>" with the path to the affected device file (from the output of the previous commands). An example device file path would be "/dev/ttyUSB0". If the output of the above command does not indicate that the device was relabeled to a more specific SELinux type label, then the SELinux policy of the system must be updated with more specific policy for the device class specified. If a package was used to install support for a device class, that package could be reinstalled using the following command:

$ sudo dnf reinstall <package_name>

If a package was not used to install the SELinux policy for a given device class, then it must be generated manually and provide specific type labels.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61673r925781_chk'
  tag severity: 'medium'
  tag gid: 'V-257932'
  tag rid: 'SV-257932r925783_rule'
  tag stig_id: 'RHEL-09-232260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61597r925782_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
