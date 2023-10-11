control 'SV-258134' do
  title 'RHEL 9 must have the AIDE package installed.'
  desc 'Without verification of the security functions, security functions may not operate correctly, and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

'
  desc 'check', %q(Verify that RHEL 9 has the Advanced Intrusion Detection Environment (AIDE) package installed with the following command:

$ sudo dnf list --installed aide

Example output:

aide.x86_64          0.16.100.el9

If AIDE is not installed, ask the system administrator (SA) how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.

If AIDE is installed, check if it has been initialized with the following command:

$ sudo /usr/sbin/aide --check

If the output is "Couldn't open file /var/lib/aide/aide.db.gz for reading", this is a finding.)
  desc 'fix', 'Install AIDE, initialize it, and perform a manual check.

Install AIDE:

$ sudo dnf install aide

Initialize AIDE:
     
$ sudo /usr/sbin/aide --init

Example output:

Start timestamp: 2023-06-05 10:09:04 -0600 (AIDE 0.16)
AIDE initialized database at /var/lib/aide/aide.db.new.gz

Number of entries:      86833

---------------------------------------------------
The attributes of the (uncompressed) database(s):
---------------------------------------------------

/var/lib/aide/aide.db.new.gz
  MD5      : coZUtPHhoFoeD7+k54fUvQ==
  SHA1     : DVpOEMWJwo0uPgrKZAygIUgSxeM=
  SHA256   : EQiZH0XNEk001tcDmJa+5STFEjDb4MPE
             TGdBJ/uvZKc=
  SHA512   : 86KUqw++PZhoPK0SZvT3zuFq9yu9nnPP
             toei0nENVELJ1LPurjoMlRig6q69VR8l
             +44EwO9eYyy9nnbzQsfG1g==

End timestamp: 2023-06-05 10:09:57 -0600 (run time: 0m 53s)

The new database will need to be renamed to be read by AIDE:

$ sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

Perform a manual check:

$ sudo /usr/sbin/aide --check

Example output:

2023-06-05 10:16:08 -0600 (AIDE 0.16)
AIDE found NO differences between database and filesystem. Looks okay!!

...'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61875r926387_chk'
  tag severity: 'medium'
  tag gid: 'V-258134'
  tag rid: 'SV-258134r926389_rule'
  tag stig_id: 'RHEL-09-651010'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-61799r926388_fix'
  tag satisfies: ['SRG-OS-000363-GPOS-00150', 'SRG-OS-000445-GPOS-00199']
  tag 'documentable'
  tag cci: ['CCI-001744', 'CCI-002696']
  tag nist: ['CM-3 (5)', 'SI-6 a']
end
