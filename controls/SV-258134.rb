control 'SV-258134' do
  title 'RHEL 9 must have the AIDE package installed.'
  desc 'Without verification of the security functions, security functions may not operate correctly, and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Selection lines in the aide.conf file determine which files and directories AIDE will monitor for changes. They follow this format:'
  desc 'check', 'Verify the file integrity tool is configured to verify ACLs.

Note: AIDE is highly configurable at install time. This requirement assumes the "aide.conf" file is under the "/etc" directory.

Verify AIDE is installed with the following command:

$ sudo dnf list installed aide

Updating Subscription Management repositories.
Installed Packages
aide.x86_64                                0.16-103.el9                                @rhel-9-for-x86_64-appstream-rpms

Use the following command to determine if the file is in a location other than "/etc/aide/aide.conf":

$ sudo find / -name aide.conf

If AIDE is not installed, ask the system administrator (SA) how file integrity checks are performed on the system.'
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
  tag check_id: 'C-61875r1155619_chk'
  tag severity: 'medium'
  tag gid: 'V-258134'
  tag rid: 'SV-258134r1155620_rule'
  tag stig_id: 'RHEL-09-651010'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-61799r926388_fix'
  tag 'documentable'
  tag cci: ['CCI-002696', 'CCI-001744']
  tag nist: ['SI-6 a', 'CM-3 (5)']
  tag 'host'

  file_integrity_tool = input('file_integrity_tool')

  only_if('Control not applicable within a container', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  if file_integrity_tool == 'aide'
    describe command('/usr/sbin/aide --check') do
      its('stdout') { should_not include "Couldn't open file" }
    end
  end

  describe package(file_integrity_tool) do
    it { should be_installed }
  end
end
