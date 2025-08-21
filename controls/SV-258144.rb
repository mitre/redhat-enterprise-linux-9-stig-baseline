control 'SV-258144' do
  title 'All RHEL 9 remote access methods must be monitored.'
  desc 'Logging remote access methods can be used to trace the decrease in the risks associated with remote user access management. It can also be used to spot cyberattacks and ensure ongoing compliance with organizational policies surrounding the use of remote access methods.'
  desc 'check', %q(Verify that RHEL 9 monitors all remote access methods.

Check that remote access methods are being logged by running the following command:

$ grep -rE '(auth.\*|authpriv.\*|daemon.\*)' /etc/rsyslog.conf /etc/rsyslog.d/

/etc/rsyslog.conf:authpriv.*

If "auth.*", "authpriv.*" or "daemon.*" are not configured to be logged, this is a finding.)
  desc 'fix', 'Add or update the following lines to the "/etc/rsyslog.conf" file or a file in "/etc/rsyslog.d":

auth.*;authpriv.*;daemon.* /var/log/secure

The "rsyslog" service must be restarted for the changes to take effect with the following command:

$ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag gid: 'V-258144'
  tag rid: 'SV-258144r1045286_rule'
  tag stig_id: 'RHEL-09-652030'
  tag fix_id: 'F-61809r1045285_fix'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable; remote access not configured within containerized RHEL', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  rsyslog = file('/etc/rsyslog.conf')

  describe rsyslog do
    it { should exist }
  end

  if rsyslog.exist?

    auth_pattern = %r{^\s*[a-z.;*]*auth(,[a-z,]+)*\.\*\s*/*}
    authpriv_pattern = %r{^\s*[a-z.;*]*authpriv(,[a-z,]+)*\.\*\s*/*}
    daemon_pattern = %r{^\s*[a-z.;*]*daemon(,[a-z,]+)*\.\*\s*/*}

    rsyslog_conf = command('grep -E \'(auth.*|authpriv.*|daemon.*)\' /etc/rsyslog.conf')

    describe 'Logged remote access methods' do
      it 'should include auth.*' do
        expect(rsyslog_conf.stdout).to match(auth_pattern), 'auth.* not configured for logging'
      end
      it 'should include authpriv.*' do
        expect(rsyslog_conf.stdout).to match(authpriv_pattern), 'authpriv.* not configured for logging'
      end
      it 'should include daemon.*' do
        expect(rsyslog_conf.stdout).to match(daemon_pattern), 'daemon.* not configured for logging'
      end
    end
  end
end
