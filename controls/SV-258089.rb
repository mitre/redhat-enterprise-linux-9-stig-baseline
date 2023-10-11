control 'SV-258089' do
  title 'RHEL 9 fapolicy module must be installed.'
  desc 'The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as allowlisting.

Utilizing an allowlist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities. Verification of allowlisted software occurs prior to execution or at system startup.

User home directories/folders may contain information of a sensitive nature. Nonprivileged users should coordinate any sharing of information with an SA through shared resources.

RHEL 9 ships with many optional packages. One such package is a file access policy daemon called "fapolicyd". "fapolicyd" is a userspace daemon that determines access rights to files based on attributes of the process and file. It can be used to either blocklist or allowlist processes or file access.

Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system nonfunctional. The "fapolicyd" API is not namespace aware and can cause issues when launching or running containers.

'
  desc 'check', 'Verify that RHEL 9 fapolicyd package is installed with the following command:

$ sudo dnf list --installed fapolicyd

Example output:

fapolicyd.x86_64          1.1-103.el9_0

If the "fapolicyd" package is not installed, this is a finding.'
  desc 'fix', 'The  fapolicyd  package can be installed with the following command:
 
$ sudo dnf install fapolicyd'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61830r926252_chk'
  tag severity: 'medium'
  tag gid: 'V-258089'
  tag rid: 'SV-258089r926254_rule'
  tag stig_id: 'RHEL-09-433010'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag fix_id: 'F-61754r926253_fix'
  tag satisfies: ['SRG-OS-000370-GPOS-00155', 'SRG-OS-000368-GPOS-00154']
  tag 'documentable'
  tag cci: ['CCI-001764', 'CCI-001774']
  tag nist: ['CM-7 (2)', 'CM-7 (5) (b)']
end
