control 'SV-257801' do
  title 'RHEL 9 must enable kernel parameters to enforce discretionary access control on hardlinks.'
  desc 'By enabling the fs.protected_hardlinks kernel parameter, users can no longer create soft or hard links to files they do not own. Disallowing such hardlinks mitigates vulnerabilities based on insecure file system accessed by privileged programs, avoiding an exploitation vector exploiting unsafe use of open() or creat().

'
  desc 'check', %q(Verify RHEL 9 is configured to enable DAC on hardlinks.

Check the status of the fs.protected_hardlinks kernel parameter with the following command:

$ sudo sysctl fs.protected_hardlinks

fs.protected_hardlinks = 1

If "fs.protected_hardlinks" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo /usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' |  grep -F fs.protected_hardlinks | tail -1

fs.protected_hardlinks = 1

If "fs.protected_hardlinks" is not set to "1" or is missing, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to enable DAC on hardlinks with the following:

Add or edit the following line in a system configuration file in the "/etc/sysctl.d/" directory:

fs.protected_hardlinks = 1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61542r925388_chk'
  tag severity: 'medium'
  tag gid: 'V-257801'
  tag rid: 'SV-257801r925390_rule'
  tag stig_id: 'RHEL-09-213030'
  tag gtitle: 'SRG-OS-000312-GPOS-00123'
  tag fix_id: 'F-61466r925389_fix'
  tag satisfies: ['SRG-OS-000312-GPOS-00123', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
end
