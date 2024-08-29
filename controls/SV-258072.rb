control 'SV-258072' do
  title 'RHEL 9 must define default permissions for the bash shell.'
  desc 'The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 600 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.

'
  desc 'check', 'Verify the "umask" setting is configured correctly in the "/etc/bashrc" file with the following command:

Note: If the value of the "umask" parameter is set to "000" "/etc/bashrc" file, the Severity is raised to a CAT I.

$ grep umask /etc/bashrc

umask 077
umask 077

If the value for the "umask" parameter is not "077", or the "umask" parameter is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to define default permissions for all authenticated users using the bash shell.

Add or edit the lines for the "umask" parameter in the "/etc/bashrc" file to "077":

umask 077'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61813r926201_chk'
  tag severity: 'medium'
  tag gid: 'V-258072'
  tag rid: 'SV-258072r926203_rule'
  tag stig_id: 'RHEL-09-412055'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-61737r926202_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00228', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host', 'container'

  file = '/etc/bashrc'

  expected_umask = input('modes_for_shells')[:bashrc_umask]

  umask_check = command("grep umask #{file}").stdout.strip.match(/^umask\s+(?<umask>\d+)$/)

  if umask_check.nil?
    describe "UMASK should be set in #{file}" do
      subject { umask_check }
      it { should_not be_nil }
    end
  else
    impact 0.7 if umask_check[:umask] == '0000' || umask_check[:umask] == '000'
    describe 'UMASK' do
      subject { umask_check[:umask] }
      it { should cmp expected_umask }
    end
  end
end
