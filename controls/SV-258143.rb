control 'SV-258143' do
  title 'RHEL 9 must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation.'
  desc "Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information into the system's logs, or could fill the system's storage leading to a denial of service.

If the system is intended to be a log aggregation server, its use must be documented with the information system security officer (ISSO)."
  desc 'check', "Note: If the system administrator can demonstrate that another tool (e.g., SPLUNK) is being used to manage log off-load and aggregation in lieu of rsyslog, this check is not applicable.

Verify RHEL 9 is not configured to receive remote logs using rsyslog with the following commands:

$ ss -tulnp | grep rsyslog

If no output is returned, rsyslog is not listening for remote messages, and is compliant.

If output appears, check for configured ports (514 is the default for syslog).

Check for remote logging configuration in rsyslog by examining the rsyslog configuration files:

$ sudo grep -E 'InputTCPServerRun | UDPServerRun | RELPServerRun | imtcp | imudp | imrelp' /etc/rsyslog.conf /etc/rsyslog.d/*

If this command returns uncommented lines enabling network listeners, the system is accepting remote logs.  If this system is not documented and authorized as a log aggregation server, this is a finding."
  desc 'fix', 'Configure RHEL 9 to not receive remote logs using rsyslog.

Remove the lines in /etc/rsyslog.conf and any files in the /etc/rsyslog.d directory that match any of the following:
InputTCPServerRun
UDPServerRun
RELPServerRun
module(load="imtcp")
module(load="imudp")
module(load="imrelp")
input(type="imudp" port="514")
input(type="imtcp" port="514")
input(type="imrelp" port="514")

The rsyslog daemon must be restarted for the changes to take effect:

$ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag check_id: 'C-61884r1155669_chk'
  tag severity: 'medium'
  tag gid: 'V-258143'
  tag rid: 'SV-258143r1155671_rule'
  tag stig_id: 'RHEL-09-652025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61808r1155670_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('is_log_aggregation_server') == true
    impact 0.0
    describe 'N/A' do
      skip 'This control is NA because the system is a log aggregation server.'
    end
  elsif input('alternative_logging_method') != ''
    impact 0.0
    describe 'N/A' do
      skip 'The system is using an approved alternative logging method; this control is Not Applicable.'
    end
  else
    rsyslog_config_files = input('logging_conf_files').join(' ')
    active_rsyslog_config = command("grep -hsv '^[[:space:]]*#' #{rsyslog_config_files}").stdout
    remote_modules = active_rsyslog_config.scan(/(?:^\s*[$]ModLoad\s+im(?:tcp|udp|relp)\b|module\s*\((?=[^)]*\bload\s*=\s*"im(?:tcp|udp|relp)")[^)]*\))/im)
    legacy_serverrun = active_rsyslog_config.lines.grep(/(?:\A\s*[$])?(?:InputTCPServerRun|UDPServerRun|RELPServerRun)\b/i)
    remote_inputs = active_rsyslog_config.scan(/input\s*\((?=[^)]*\btype\s*=\s*"im(?:tcp|udp|relp)")[^)]*\)/im)

    describe 'remote rsyslog input modules' do
      it 'is not configured to receive remote logs' do
        expect(remote_modules).to be_empty, "Remote rsyslog input module settings found:\n#{remote_modules.join}"
      end
    end
    describe 'legacy rsyslog listener configuration' do
      it 'is not configured to receive remote logs' do
        expect(legacy_serverrun).to be_empty, "Legacy rsyslog listener settings found:\n#{legacy_serverrun.join}"
      end
    end
    describe 'RainerScript rsyslog listener configuration' do
      it 'is not configured to receive remote logs' do
        expect(remote_inputs).to be_empty, "RainerScript rsyslog listener settings found:\n#{remote_inputs.join}"
      end
    end
  end
end
