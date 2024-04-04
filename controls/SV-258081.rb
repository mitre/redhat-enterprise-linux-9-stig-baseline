control 'SV-258081' do
  title 'RHEL 8 must have policycoreutils package installed.'
  desc 'Without verification of the security functions, security functions may
not operate correctly and the failure may go unnoticed. Security function is
defined as the hardware, software, and/or firmware of the information system
responsible for enforcing the system security policy and supporting the
isolation of code and data on which the protection is based. Security
functionality includes, but is not limited to, establishing system accounts,
configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

    Policycoreutils contains the policy core utilities that are required for
basic operation of an SELinux-enabled system. These utilities include
load_policy to load SELinux policies, setfile to label filesystems, newrole to
switch roles, and run_init to run /etc/init.d scripts in the proper context.'
  desc 'check', 'Verify the operating system has the policycoreutils package installed with
the following command:

    $ sudo yum list installed policycoreutils

    policycoreutils.x86_64
2.9-3.el8                                                  @anaconda

    If the policycoreutils package is not installed, this is a finding.'
  desc 'fix', 'Configure the operating system to have the policycoreutils package
installed with the following command:

    $ sudo yum install policycoreutils'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag gid: 'V-230241'
  tag rid: 'SV-258081r627750_rule'
  tag stig_id: 'RHEL-08-010171'
  tag fix_id: 'F-32885r567470_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  describe package('policycoreutils') do
    it { should be_installed }
  end
end
