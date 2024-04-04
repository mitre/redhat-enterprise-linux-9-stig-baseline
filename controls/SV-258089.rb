control 'SV-258089' do
  title 'The RHEL 8 fapolicy module must be installed.'
  desc 'The organization must identify authorized software programs and permit
execution of authorized software. The process used to identify software
programs that are authorized to execute on organizational information systems
is commonly referred to as whitelisting.

    Utilizing a whitelist provides a configuration management method for
allowing the execution of only authorized software. Using only authorized
software decreases risk by limiting the number of potential vulnerabilities.
Verification of whitelisted software occurs prior to execution or at system
startup.

    User home directories/folders may contain information of a sensitive
nature. Non-privileged users should coordinate any sharing of information with
an SA through shared resources.

    RHEL 8 ships with many optional packages. One such package is a file access
policy daemon called "fapolicyd". "fapolicyd" is a userspace daemon that
determines access rights to files based on attributes of the process and file.
It can be used to either blacklist or whitelist processes or file access.

    Proceed with caution with enforcing the use of this daemon. Improper
configuration may render the system non-functional. The "fapolicyd" API is
not namespace aware and can cause issues when launching or running containers.'
  desc 'check', 'Verify the RHEL 8 "fapolicyd" is installed.

Check that "fapolicyd" is installed with the following command:

$ sudo yum list installed fapolicyd

Installed Packages
fapolicyd.x86_64

If fapolicyd is not installed, this is a finding.'
  desc 'fix', 'Install "fapolicyd" with the following command:

$ sudo yum install fapolicyd.x86_64'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155', 'SRG-OS-000480-GPOS-00232']
  tag gid: 'V-230523'
  tag rid: 'SV-258089r854064_rule'
  tag stig_id: 'RHEL-08-040135'
  tag fix_id: 'F-33167r744022_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if !input('use_fapolicyd')
    impact 0.0
    describe 'The organization is not using the Fapolicyd service to manage firewall servies, this control is Not Applicable' do
      skip 'The organization is not using the Fapolicyd service to manage firewall servies, this control is Not Applicable'
    end
  else
    describe package('fapolicyd') do
      it { should be_installed }
    end
  end
end
