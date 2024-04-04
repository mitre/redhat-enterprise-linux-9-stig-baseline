control 'SV-258078' do
  title 'RHEL 8 must use a Linux Security Module configured to enforce limits
on system services.'
  desc 'Without verification of the security functions, security functions may
not operate correctly and the failure may go unnoticed. Security function is
defined as the hardware, software, and/or firmware of the information system
responsible for enforcing the system security policy and supporting the
isolation of code and data on which the protection is based. Security
functionality includes, but is not limited to, establishing system accounts,
configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

    This requirement applies to operating systems performing security function
verification/testing and/or systems and environments that require this
functionality.'
  desc 'check', 'Verify the operating system verifies correct operation of all security
functions.

    Check if "SELinux" is active and in "Enforcing" mode with the following
command:

    $ sudo getenforce
    Enforcing

    If "SELinux" is not active and not in "Enforcing" mode, this is a
finding.'
  desc 'fix', 'Configure the operating system to verify correct operation of all security
functions.

    Set the "SELinux" status and the "Enforcing" mode by modifying the
"/etc/selinux/config" file to have the following line:

    SELINUX=enforcing

    A reboot is required for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag gid: 'V-230240'
  tag rid: 'SV-258078r627750_rule'
  tag stig_id: 'RHEL-08-010170'
  tag fix_id: 'F-32884r567467_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  describe selinux do
    it { should be_enforcing }
  end
end
