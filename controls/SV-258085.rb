control 'SV-258085' do
  title %q(RHEL 8 must use the invoking user's password for privilege escalation
when using "sudo".)
  desc %q(The sudoers security policy requires that users authenticate
themselves before they can use sudo. When sudoers requires authentication, it
validates the invoking user's credentials. If the rootpw, targetpw, or runaspw
flags are defined and not disabled, by default the operating system will prompt
the invoking user for the "root" user password.
    For more information on each of the listed configurations, reference the
sudoers(5) manual page.)
  desc 'check', %q(Verify that the sudoers security policy is configured to use the invoking user's password for privilege escalation.

     $ sudo grep -Eir '(rootpw|targetpw|runaspw)' /etc/sudoers /etc/sudoers.d* | grep -v '#'

     /etc/sudoers:Defaults !targetpw
     /etc/sudoers:Defaults !rootpw
     /etc/sudoers:Defaults !runaspw

If conflicting results are returned, this is a finding.
If "Defaults !targetpw" is not defined, this is a finding.
If "Defaults !rootpw" is not defined, this is a finding.
If "Defaults !runaspw" is not defined, this is a finding.)
  desc 'fix', 'Define the following in the Defaults section of the /etc/sudoers file or a configuration file in the /etc/sudoers.d/ directory:
     Defaults !targetpw
     Defaults !rootpw
     Defaults !runaspw

Remove any configurations that conflict with the above from the following locations:
     /etc/sudoers
     /etc/sudoers.d/'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-237642'
  tag rid: 'SV-258085r880727_rule'
  tag stig_id: 'RHEL-08-010383'
  tag fix_id: 'F-40824r880726_fix'
  tag cci: ['CCI-002227']
  tag nist: ['AC-6 (5)']
  tag 'host'

  only_if('This control is Not Applicable to containers without sudo installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !command('sudo').exist?)
  }

  settings = sudoers(input('sudoers_config_files').join(' ')).settings['Defaults']

  describe 'Sudoers file(s) settings' do
    it 'should set !targetpw' do
      expect(settings).to include('!targetpw'), 'Sudoers file(s) do not set !targetpw'
      expect(settings).not_to include('targetpw'), 'Sudoers file(s) set targetpw'
    end
    it 'should set !rootpw' do
      expect(settings).to include('!rootpw'), 'Sudoers file(s) do not set !rootpw'
      expect(settings).not_to include('rootpw'), 'Sudoers file(s) set rootpw'
    end
    it 'should set !runaspw' do
      expect(settings).to include('!runaspw'), 'Sudoers file(s) do not set !runaspw'
      expect(settings).not_to include('runaspw'), 'Sudoers file(s) set runaspw'
    end
  end
end
