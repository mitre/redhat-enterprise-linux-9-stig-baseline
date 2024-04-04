control 'SV-258144' do
  title 'All RHEL 8 remote access methods must be monitored.'
  desc 'Remote access services, such as those providing remote access to
network devices and information systems, which lack automated monitoring
capabilities, increase risk and make remote user access management difficult at
best.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    Automated monitoring of remote access sessions allows organizations to
detect cyber attacks and ensure ongoing compliance with remote access policies
by auditing connection activities of remote access capabilities, such as Remote
Desktop Protocol (RDP), on a variety of information system components (e.g.,
servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', %q(Verify that RHEL 8 monitors all remote access methods.

    Check that remote access methods are being logged by running the following
command:

    $ sudo grep -E '(auth.*|authpriv.*|daemon.*)' /etc/rsyslog.conf

    auth.*;authpriv.*;daemon.* /var/log/secure

    If "auth.*", "authpriv.*" or "daemon.*" are not configured to be
logged, this is a finding.)
  desc 'fix', 'Configure RHEL 8 to monitor all remote access methods by installing rsyslog
with the following command:

    $ sudo yum install rsyslog

    Then add or update the following lines to the "/etc/rsyslog.conf" file:

    auth.*;authpriv.*;daemon.* /var/log/secure

    The "rsyslog" service must be restarted for the changes to take effect.
To restart the "rsyslog" service, run the following command:

    $ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag gid: 'V-230228'
  tag rid: 'SV-258144r627750_rule'
  tag stig_id: 'RHEL-08-010070'
  tag fix_id: 'F-32872r567431_fix'
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
