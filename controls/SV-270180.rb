control 'SV-270180' do
  title 'The RHEL 9 fapolicy module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  desc 'The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as allow listing.

Using an allow list provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities. Verification of allow listed software occurs prior to execution or at system startup.

User home directories/folders may contain information of a sensitive nature. Nonprivileged users should coordinate any sharing of information with an SA through shared resources.

RHEL 9 ships with many optional packages. One such package is a file access policy daemon called "fapolicyd". "fapolicyd" is a userspace daemon that determines access rights to files based on attributes of the process and file. It can be used to either block list or allow list processes or file access.

Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system nonfunctional. The "fapolicyd" API is not namespace aware and can cause issues when launching or running containers.

'
  desc 'check', 'Verify the RHEL 9 "fapolicyd" employs a deny-all, permit-by-exception policy.

Check that "fapolicyd" is in enforcement mode with the following command:

$ sudo grep permissive /etc/fapolicyd/fapolicyd.conf

permissive = 0

Check that "fapolicyd" employs a deny-all policy on system mounts with the following commands:

$ sudo tail /etc/fapolicyd/compiled.rules

allow exe=/usr/bin/python3.7 : ftype=text/x-python
deny_audit perm=any pattern=ld_so : all
deny perm=any all : all

If "fapolicyd" is not running in enforcement mode with a deny-all, permit-by-exception policy, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to employ a deny-all, permit-by-exception application allow listing policy with "fapolicyd".

With the "fapolicyd" installed and enabled, configure the daemon to function in permissive mode until the allow list is built correctly to avoid system lockout. Do this by editing the "/etc/fapolicyd/fapolicyd.conf" file with the following line:

permissive = 1

Build the allow list in a file within the "/etc/fapolicyd/rules.d" directory, ensuring the last rule is "deny perm=any all : all".

Once it is determined the allow list is built correctly, set the "fapolicyd" to enforcing mode by editing the "permissive" line in the /etc/fapolicyd/fapolicyd.conf file.

permissive = 0'
  impact 0.5
  tag check_id: 'C-74213r1045180_chk'
  tag severity: 'medium'
  tag gid: 'V-270180'
  tag rid: 'SV-270180r1045182_rule'
  tag stig_id: 'RHEL-09-433016'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-74114r1045181_fix'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155', 'SRG-OS-000480-GPOS-00232']
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']

  describe file('/etc/fapolicyd/fapolicyd.conf') do
    its('content') { should include 'permissive = 0' }
  end

  describe file('/etc/fapolicyd/compiled.rules') do
    its('content') { should include 'allow exe=/usr/bin/python3.7 : ftype=text/x-python' }
    its('content') { should include 'deny_audit perm=any pattern=ld_so : all' }
    its('content') { should include 'deny perm=any all : all' }
  end
end
