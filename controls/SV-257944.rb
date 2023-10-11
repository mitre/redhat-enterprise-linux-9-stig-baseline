control 'SV-257944' do
  title 'RHEL 9 chronyd service must be enabled.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Verify the chronyd service is active with the following command:

$ systemctl is-active chronyd

active 

If the chronyd service is not active, this is a finding.'
  desc 'fix', 'To enable the chronyd service run the following command:

$ sudo systemctl enable --now chronyd'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag check_id: 'C-61685r925817_chk'
  tag severity: 'medium'
  tag gid: 'V-257944'
  tag rid: 'SV-257944r925819_rule'
  tag stig_id: 'RHEL-09-252015'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-61609r925818_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
