control 'SV-258150' do
  title 'RHEL 9 must use cron logging.'
  desc 'Cron logging can be used to trace the successful or unsuccessful
execution of cron jobs. It can also be used to spot intrusions into the use of
the cron facility by unauthorized and malicious users.'
  desc 'check', 'Verify that "rsyslog" is configured to log cron events with the following command:

Note: If another logging package is used, substitute the utility configuration file for "/etc/rsyslog.conf" or "/etc/rsyslog.d/*.conf" files.

$ grep -s cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf

/etc/rsyslog.conf:*.info;mail.none;authpriv.none;cron.none /var/log/messages
/etc/rsyslog.conf:cron.* /var/log/cron

If the command does not return a response, check for cron logging all facilities with the following command:

$ logger -p local0.info "Test message for all facilities."

Check the logs for the test message with:

$ sudo tail /var/log/messages

If "rsyslog" is not logging messages for the cron facility or all facilities, this is a finding.'
  desc 'fix', 'Configure "rsyslog" to log all cron messages by adding or updating the
following line to "/etc/rsyslog.conf" or a configuration file in the
/etc/rsyslog.d/ directory:

    cron.* /var/log/cron

    The rsyslog daemon must be restarted for the changes to take effect:
    $ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258150'
  tag rid: 'SV-258150r1045296_rule'
  tag stig_id: 'RHEL-09-652060'
  tag fix_id: 'F-61815r926436_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternative_logging_method') == ''
    rsyslog_config_files = input('logging_conf_files').join(' ')
    active_rsyslog_config = command("grep -hsv '^[[:space:]]*#' #{rsyslog_config_files}").stdout
    legacy_cron_rule = %r{^\s*cron\.\*\s+/var/log/cron\s*$}i
    rainer_cron_rule = %r{^\s*cron\.\*\s+action\((?=[^)]*\btype\s*=\s*"omfile")(?=[^)]*\bfile\s*=\s*"/var/log/cron")[^)]*\)\s*$}i
    legacy_messages_rule = %r{^\s*\*\.info;mail\.none;authpriv\.none;cron\.none\s+/var/log/messages\s*$}i
    rainer_messages_rule = %r{^\s*\*\.info;mail\.none;authpriv\.none;cron\.none\s+action\((?=[^)]*\btype\s*=\s*"omfile")(?=[^)]*\bfile\s*=\s*"/var/log/messages")[^)]*\)\s*$}i

    describe.one do
      describe 'Rsyslog cron logging configuration' do
        it 'logs cron events to /var/log/cron' do
          expect(active_rsyslog_config).to match(Regexp.union(legacy_cron_rule, rainer_cron_rule)), "No active cron logging rule found in #{rsyslog_config_files}"
        end
      end
      describe 'Rsyslog all-facility logging configuration' do
        it 'logs all non-cron facilities to /var/log/messages' do
          expect(active_rsyslog_config).to match(Regexp.union(legacy_messages_rule, rainer_messages_rule)), "No active /var/log/messages rule found in #{rsyslog_config_files}"
        end
      end
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
