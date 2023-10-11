control 'SV-257780' do
  title 'RHEL 9 must implement the Endpoint Security for Linux Threat Prevention tool.'
  desc 'Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the operating system may have an integrated solution incorporating continuous scanning using ESS and periodic scanning using other tools, as specified in the requirement.'
  desc 'check', 'Verify that RHEL 9 has implemented the Endpoint Security for Linux Threat Prevention tool.

Check that the following package has been installed:

$ sudo rpm -qa | grep -i mcafeetp

If the "mcafeetp" package is not installed, this is a finding.

Verify that the daemon is running:

$ sudo ps -ef | grep -i mfetpd

If the daemon is not running, this is a finding.'
  desc 'fix', 'Install and enable the latest McAfee ENSLTP package.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61521r925325_chk'
  tag severity: 'medium'
  tag gid: 'V-257780'
  tag rid: 'SV-257780r925327_rule'
  tag stig_id: 'RHEL-09-211025'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-61445r925326_fix'
  tag 'documentable'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
