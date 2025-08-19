control 'SV-258143' do
  title 'RHEL 9 must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation.'
  desc "Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information into the system's logs, or could fill the system's storage leading to a denial of service.

If the system is intended to be a log aggregation server, its use must be documented with the information system security officer (ISSO)."
  desc 'check', %q(Verify that RHEL 9 is not configured to receive remote logs using rsyslog with the following commands:

$ grep -i modload /etc/rsyslog.conf /etc/rsyslog.d/*

$ModLoad imtcp
$ModLoad imrelp
$ModLoad imudp

$ grep -i 'load="imtcp"' /etc/rsyslog.conf /etc/rsyslog.d/*

$ grep -i 'load="imrelp"' /etc/rsyslog.conf /etc/rsyslog.d/*

$ grep -i serverrun /etc/rsyslog.conf /etc/rsyslog.d/*

$InputTCPServerRun 514
$InputRELPServerRun 514
$InputUDPServerRun 514

$ grep -i 'port="\S*"' /etc/rsyslog.conf /etc/rsyslog.d/*

/etc/rsyslog.conf:#input(type="imudp" port="514")
/etc/rsyslog.conf:#input(type="imtcp" port="514")
/etc/rsyslog.conf:#Target="remote_host" Port="XXX" Protocol="tcp")

  'If any uncommented lines are returned by the commands, rsyslog is configured to receive remote messages, and this is a finding.

Note: An error about no files or directories from the above commands may be returned. This is not a finding.

If any modules are being loaded in the "/etc/rsyslog.conf" file or in the "/etc/rsyslog.d" subdirectories, ask to see the documentation for the system being used for log aggregation.

If the documentation does not exist or does not specify the server as a log aggregation system, this is a finding.)'
  desc 'fix', 'Configure RHEL 9 to not receive remote logs using rsyslog.

Remove the lines in /etc/rsyslog.conf and any files in the /etc/rsyslog.d directory that match any of the following:
module(load="imtcp")
module(load="imudp")
module(load="imrelp")
input(type="imudp" port="514")
input(type="imtcp" port="514")
input(type="imrelp" port="514")

The rsyslog daemon must be restarted for the changes to take effect:

$ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag check_id: 'C-61884r1045281_chk'
  tag severity: 'medium'
  tag gid: 'V-258143'
  tag rid: 'SV-258143r1045283_rule'
  tag stig_id: 'RHEL-09-652025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-61808r1045282_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  if input('is_log_aggregation_server')
    impact 0.0
    describe 'N/A' do
      skip 'This control is NA because the system is a log aggregation server.'
    end
  else
    modload = command('grep -i modload /etc/rsyslog.conf /etc/rsyslog.d/*').stdout.strip
    imtcp = command(%q(grep -i 'load="imtcp"' /etc/rsyslog.conf /etc/rsyslog.d/*)).stdout.strip
    imrelp = command(%q(grep -i 'load="imrelp"' /etc/rsyslog.conf /etc/rsyslog.d/*)).stdout.strip
    serverrun = command('grep -i serverrun /etc/rsyslog.conf /etc/rsyslog.d/*').stdout.strip
    ports = command(%q(grep -i 'port="\S*"' /etc/rsyslog.conf /etc/rsyslog.d/*)).stdout.strip

    describe 'modload' do
      it 'is not configured to receive remote logs' do
        expect(modload).to be_empty, "modload settings found:\n#{modload}"
      end
    end
    describe 'imtcp' do
      it 'is not configured to receive remote logs' do
        expect(imtcp).to be_empty, "imtcp settings found:\n#{imtcp}"
      end
    end
    describe 'imrelp' do
      it 'is not configured to receive remote logs' do
        expect(imrelp).to be_empty, "imrelp settings found:\n#{imrelp}"
      end
    end
    describe 'serverrun config' do
      it 'is not configured to receive remote logs' do
        expect(serverrun).to be_empty, "serverrun settings found:\n#{serverrun}"
      end
    end
    describe 'ports' do
      it 'are not configured to receive remote logs' do
        expect(ports).to be_empty, "port settings found:\n#{ports}"
      end
    end
  end
end
