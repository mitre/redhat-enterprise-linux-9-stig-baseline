control 'SV-258134' do
  title 'The RHEL 8 operating system must use a file integrity tool to verify correct operation of all security functions.'
  desc 'Without verification of the security functions, security functions may not operate correctly, and the failure may go unnoticed.
        Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the
        system security policy and supporting the isolation of code and data on which the protection is based. Security functionality
        includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges),
        setting events to be audited, and setting intrusion detection parameters.

        This requirement applies to the RHEL 8 operating system performing security function verification/testing and/or systems and
        environments that require this functionality.'
  desc 'check', %q(Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all
        security functions.

        Check that the AIDE package is installed with the following command:
          $ sudo rpm -q aide

          aide-0.16-14.el8_5.1.x86_64

        If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.

        If there is no application installed to perform integrity checks, this is a finding.

        If AIDE is installed, check if it has been initialized with the following command:
          $ sudo /usr/sbin/aide --check

        If the output is "Couldn't open file /var/lib/aide/aide.db.gz for reading", this is a finding.)
  desc 'fix', 'Install AIDE, initialize it, and perform a manual check.

        Install AIDE:
          $ sudo yum install aide

        Initialize it:
          $ sudo /usr/sbin/aide --init

        Example output:
          Number of entries:      48623

          ---------------------------------------------------
          The attributes of the (uncompressed) database(s):
          ---------------------------------------------------

          /var/lib/aide/aide.db.new.gz
            SHA1     : LTAVQ8tFJthsrf4m9gfRpnf1vyc=
            SHA256   : NJ9+uzRQKSwmLQ8A6IpKNvYjVKGbhSjt
              BeJBVcmOVrI=
            SHA512   : 7d8I/F6A1b07E4ZuGeilZjefRgJJ/F20
              eC2xoag1OsOVpctt3Mi7Jjjf3vFW4xoY
              5mdS6/ImQpm0xtlTLOPeQQ==

          End timestamp: 2022-10-20 10:50:52 -0700 (run time: 0m 46s)

        The new database will need to be renamed to be read by AIDE:
          $ sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

        Perform a manual check:
          $ sudo /usr/sbin/aide --check

        Example output:
          Start timestamp: 2022-10-20 11:03:16 -0700 (AIDE 0.16)
          AIDE found differences between database and filesystem!!
          ...

        Done.'
  impact 0.5
  tag check_id: 'C-55147r880728_chk'
  tag severity: 'medium'
  tag gid: 'V-251710'
  tag rid: 'SV-258134r880730_rule'
  tag stig_id: 'RHEL-08-010359'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-55101r880729_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
  tag 'host'

  file_integrity_tool = input('file_integrity_tool')

  only_if('Control not applicable within a container', impact: 0.0) do
    !virtualization.system.eql?('docker')
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
