control 'SV-257946' do
  title 'RHEL 8 must disable the chrony daemon from acting as a server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Minimizing the exposure of the server functionality of the chrony daemon diminishes the attack surface.

RHEL 8 utilizes the "timedatectl" command to view the status of the "systemd-timesyncd.service". The "timedatectl" status will display the local time, UTC, and the offset from UTC.

Note that USNO offers authenticated NTP service to DOD and U.S. Government agencies operating on the NIPR and SIPR networks. Visit https://www.usno.navy.mil/USNO/time/ntp/DOD-customers for more information.'
  desc 'check', %q(Note: If the system is approved and documented by the information system security officer (ISSO) to function as an NTP time server, this requirement is Not Applicable.

Verify RHEL 8 disables the chrony daemon from acting as a server with the following command:

     $ sudo grep -w 'port' /etc/chrony.conf
     port 0

If the "port" option is not set to "0", is commented out or missing, this is a finding.)
  desc 'fix', 'Configure the operating system to disable the chrony daemon from acting as a server by adding or modifying the following line in the "/etc/chrony.conf" file:

     port 0'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-230485'
  tag rid: 'SV-257946r928590_rule'
  tag stig_id: 'RHEL-08-030741'
  tag fix_id: 'F-33129r928589_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/chrony.conf').exist?)
  }

  chrony_conf = ntp_conf('/etc/chrony.conf')

  describe chrony_conf do
    its('port') { should cmp 0 }
  end
end
