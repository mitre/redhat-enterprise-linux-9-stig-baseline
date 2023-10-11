control 'SV-257945' do
  title 'RHEL 9 must securely compare internal information system clocks at least every 24 hours.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Depending on the infrastructure being used the "pool" directive may not be supported.

Authoritative time sources include the United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).

'
  desc 'check', 'Verify RHEL 9 is securely comparing internal information system clocks at least every 24 hours with an NTP server with the following commands:

$ sudo grep maxpoll /etc/chrony.conf

server 0.us.pool.ntp.mil iburst maxpoll 16

If the "maxpoll" option is set to a number greater than 16 or the line is commented out, this is a finding.

Verify the "chrony.conf" file is configured to an authoritative DOD time source by running the following command:

$ sudo grep -i server /etc/chrony.conf
server 0.us.pool.ntp.mil 

If the parameter "server" is not set or is not set to an authoritative DOD time source, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to securely compare internal information system clocks at least every 24 hours with an NTP server by adding/modifying the following line in the /etc/chrony.conf file.

server [ntp.server.name] iburst maxpoll 16'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61686r925820_chk'
  tag severity: 'medium'
  tag gid: 'V-257945'
  tag rid: 'SV-257945r925822_rule'
  tag stig_id: 'RHEL-09-252020'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-61610r925821_fix'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144', 'SRG-OS-000359-GPOS-00146']
  tag 'documentable'
  tag cci: ['CCI-001890', 'CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 b', 'AU-8 (1) (a)', 'AU-8 (1) (b)']
end
