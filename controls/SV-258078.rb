control 'SV-258078' do
  title 'RHEL 9 must use a Linux Security Module configured to enforce limits on system services.'
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
  desc 'check', 'Ensure that RHEL 9 verifies correct operation of security functions through the use of SELinux with the following command:

$ getenforce

Enforcing

If SELINUX is not set to "Enforcing", this is a finding.

Verify that SELinux is configured to be enforcing at boot.

grep "SELINUX=" /etc/selinux/config
# SELINUX= can take one of these three values:
# NOTE: In earlier Fedora kernel builds, SELINUX=disabled would also
SELINUX=enforcing

If SELINUX line is missing, commented out, or not set to "enforcing", this is a finding.'
  desc 'fix', 'Configure RHEL 9 to verify correct operation of security functions.

Edit the file "/etc/selinux/config" and add or modify the following line:

 SELINUX=enforcing

A reboot is required for the changes to take effect.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag gid: 'V-258078'
  tag rid: 'SV-258078r926221_rule'
  tag stig_id: 'RHEL-09-431010'
  tag fix_id: 'F-61743r926220_fix'
  tag cci: ['CCI-001084', 'CCI-002696']
  tag nist: ['SC-3', 'SI-6 a']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  describe selinux do
    it { should be_enforcing }
  end
end
