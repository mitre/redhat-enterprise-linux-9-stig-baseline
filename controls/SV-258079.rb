control 'SV-258079' do
  title 'RHEL 8 must enable the SELinux targeted policy.'
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
  desc 'check', %q(Ensure the operating system verifies correct operation of all security
functions.

    Check if "SELinux" is active and is enforcing the targeted policy with
the following command:

    $ sudo sestatus

    SELinux status: enabled
    SELinuxfs mount: /sys/fs/selinux
    SELinux root directory: /etc/selinux
    Loaded policy name: targeted
    Current mode: enforcing
    Mode from config file: enforcing
    Policy MLS status: enabled
    Policy deny_unknown status: allowed
    Memory protection checking: actual (secure)
    Max kernel policy version: 31

    If the "Loaded policy name" is not set to "targeted", this is a finding.

    Verify that the /etc/selinux/config file is configured to the
"SELINUXTYPE" to "targeted":

    $ sudo grep -i "selinuxtype" /etc/selinux/config | grep -v '^#'

    SELINUXTYPE = targeted

    If no results are returned or "SELINUXTYPE" is not set to "targeted",
this is a finding.)
  desc 'fix', 'Configure the operating system to verify correct operation of all security
functions.

    Set the "SELinuxtype" to the "targeted" policy by modifying the
"/etc/selinux/config" file to have the following line:

    SELINUXTYPE=targeted

    A reboot is required for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag gid: 'V-230282'
  tag rid: 'SV-258079r854035_rule'
  tag stig_id: 'RHEL-08-010450'
  tag fix_id: 'F-32926r567593_fix'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe selinux do
    it { should_not be_disabled }
    it { should be_enforcing }
    its('policy') { should eq 'targeted' }
  end

  describe parse_config_file('/etc/selinux/config') do
    its('SELINUXTYPE') { should eq 'targeted' }
  end
end
