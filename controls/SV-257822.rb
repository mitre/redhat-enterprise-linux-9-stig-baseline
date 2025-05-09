control 'SV-257822' do
  title 'RHEL 9 must have GPG signature verification enabled for all software repositories.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

All software packages must be signed with a cryptographic key recognized and approved by the organization.

Verifying the authenticity of software prior to installation validates the integrity of the software package received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor.'
  desc 'check', 'Verify that all software repositories defined in "/etc/yum.repos.d/" have been configured with "gpgcheck" enabled:

$ grep -w gpgcheck /etc/yum.repos.d/*.repo | more

gpgcheck = 1

If "gpgcheck" is not set to "1" for all returned lines, this is a finding.'
  desc 'fix', %q(Configure all software repositories defined in "/etc/yum.repos.d/" to have "gpgcheck" enabled:

$ sudo sed -i 's/gpgcheck\s*=.*/gpgcheck=1/g' /etc/yum.repos.d/*)
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61563r1044879_chk'
  tag severity: 'high'
  tag gid: 'V-257822'
  tag rid: 'SV-257822r1044880_rule'
  tag stig_id: 'RHEL-09-214025'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-61487r925452_fix'
  tag 'documentable'
  tag cci: ['CCI-001749', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-14']
  tag 'host'
  tag 'container'

  repo_def_files = command('ls /etc/yum.repos.d/*.repo').stdout.split("\n")

  if repo_def_files.empty?
    describe 'No repos found in /etc/yum.repos.d/*.repo' do
      skip 'No repos found in /etc/yum.repos.d/*.repo'
    end
  else
    # pull out all repo definitions from all files into one big hash
    repos = repo_def_files.map { |file| parse_config_file(file).params }.inject(&:merge)

    # check big hash for repos that fail the test condition
    failing_repos = repos.keys.reject { |repo_name| repos[repo_name]['gpgcheck'] == '1' }

    describe 'All repositories' do
      it 'should be configured to verify digital signatures' do
        expect(failing_repos).to be_empty, "Misconfigured repositories:\n\t- #{failing_repos.join("\n\t- ")}"
      end
    end
  end
end
