control 'SV-258004' do
  title 'RHEL 9 SSH daemon must not allow Kerberos authentication.'
  desc "Kerberos authentication for SSH is often implemented using Generic Security Service Application Program Interface (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation. Vulnerabilities in the system's Kerberos implementations may be subject to exploitation."
  desc 'check', 'Verify the SSH daemon does not allow Kerberos authentication with the following command:

$ sudo grep -i kerberosauth  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*

KerberosAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, and the use of Kerberos authentication has not been documented with the information system security officer (ISSO), this is a finding.'
  desc 'fix', 'Configure the SSH daemon to not allow Kerberos authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "no":

KerberosAuthentication no

The SSH service must be restarted for changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag gid: 'V-258004'
  tag rid: 'SV-258004r925999_rule'
  tag stig_id: 'RHEL-09-255140'
  tag fix_id: 'F-61669r925998_fix'
  tag cci: ['CCI-000366', 'CCI-001813']
  tag nist: ['CM-6 b', 'CM-5 (1) (a)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  use_kerberos = input('kerberos_required') ? 'yes' : 'no'

  describe sshd_config do
    its('KerberosAuthentication') { should cmp use_kerberos }
  end
end
