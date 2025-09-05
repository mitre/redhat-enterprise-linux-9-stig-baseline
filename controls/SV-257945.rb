control 'SV-257945' do
  title 'RHEL 9 must securely compare internal information system clocks at least every 24 hours.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Depending on the infrastructure being used the "pool" directive may not be supported.

Authoritative time sources include the United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
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
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144', 'SRG-OS-000359-GPOS-00146']
  tag gid: 'V-257945'
  tag rid: 'SV-257945r925822_rule'
  tag stig_id: 'RHEL-09-252020'
  tag fix_id: 'F-61610r925821_fix'
  tag cci: ['CCI-001891', 'CCI-001890', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 b', 'AU-8 (1) (b)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  # Get inputs
  authoritative_timeservers = [input('authoritative_timeservers')].flatten
  match_all_authoritative_timeservers_enabled = input('match_all_authoritative_timeservers_enabled')

  # Get the system server values (might be part of a pool)
  # Converts to array if only one value present
  time_sources = []
  time_sources = [chrony_conf.server].flatten if chrony_conf.server
  time_sources += chrony_conf.pool if chrony_conf.pool

  # Get and map maxpoll values to an array
  unless time_sources.nil?
    # Map max poll values only
    max_poll_values = time_sources.map { |val|
      val.match?(/.*maxpoll.*/) ? val.gsub(/.*maxpoll\s+(\d+)(\s+.*|$)/, '\1').to_i : 10
    }

    # Map server values only
    server_values = time_sources.map { |val|
      val.split.first
    }
  end

  # Verify the "chrony.conf" file is configured to a time source by running the following command:
  describe.one do
    describe chrony_conf do
      its('server') { should_not be_nil }
    end
    describe chrony_conf do
      its('pool') { should_not be_nil }
    end
  end

  unless time_sources.nil?
    # Verify the chrony.conf file is configured to at least one authoritative DoD time source
    # Check for valid maxpoll value <17
    describe 'chrony.conf' do
      # authoritative_timeservers_exact specifies whether to verify all inputted timeservers or just one
      if match_all_authoritative_timeservers_enabled
        it 'should include all specified valid timeservers' do
          expect(authoritative_timeservers.all? { |input|
                   server_values.include?(input) && max_poll_values[server_values.index(input)] <= 16
                 }).to be true
        end
      else
        it 'should include at least one valid timeserver' do
          expect(authoritative_timeservers.any? { |input|
            server_values.include?(input) && max_poll_values[server_values.index(input)] <= 16
          }).to be true
        end
      end
    end
  end
end
