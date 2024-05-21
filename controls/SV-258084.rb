control 'SV-258084' do
  title 'RHEL 9 must require reauthentication when using the "sudo" command.'
  desc %q(Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the organization requires the user to reauthenticate when using the "sudo" command.

If the value is set to an integer less than "0", the user's time stamp will not expire and the user will not have to reauthenticate for privileged actions until the user's session is terminated.)
  desc 'check', %q(Verify RHEL 9 requires reauthentication when using the "sudo" command to elevate privileges with the following command:

$ sudo grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/*

/etc/sudoers:Defaults timestamp_timeout=0

If results are returned from more than one file location, this is a finding.

If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a finding.)
  desc 'fix', 'Configure RHEL 9 to reauthenticate "sudo" commands after the specified timeout:

Add the following line to "/etc/sudoers":

Defaults timestamp_timeout=0'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag gid: 'V-258084'
  tag rid: 'SV-258084r943061_rule'
  tag stig_id: 'RHEL-09-432015'
  tag fix_id: 'F-61749r926238_fix'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
  tag 'host'
  tag 'container-conditional'

  only_if('This requirement is Not Applicable in a container with no sudo installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !command('sudo').exist?)
  }

  setting = 'timestamp_timeout'
  setting_value = sudoers(input('sudoers_config_files')).settings.Defaults[setting]

  describe 'Sudoers configuration' do
    it "should should set #{setting} to a non-negative number, exactly once" do
      expect(setting_value).to_not be_nil, "#{setting} not found inside sudoers config file(s)"
      expect(setting_value.count).to eq(1), "#{setting} set #{setting_value.count} times inside sudoers config file(s)"
      expect(setting_value.first.to_i).to be >= 0
    end
  end
end
