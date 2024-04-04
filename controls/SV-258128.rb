control 'SV-258128' do
  title 'RHEL 8 operating systems must require authentication upon booting into
emergency mode.'
  desc 'If the system does not require valid root authentication before it
boots into emergency or rescue mode, anyone who invokes emergency or rescue
mode is granted privileged access to all files on the system.'
  desc 'check', 'Check to see if the system requires authentication for emergency mode with
the following command:

    $ sudo grep sulogin-shell /usr/lib/systemd/system/emergency.service

    ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency

    If the "ExecStart" line is configured for anything other than
"/usr/lib/systemd/systemd-sulogin-shell emergency", commented out, or
missing, this is a finding.'
  desc 'fix', 'Configure the system to require authentication upon booting into emergency
mode by adding the following line to the
"/usr/lib/systemd/system/emergency.service" file.

    ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-244523'
  tag rid: 'SV-258128r743818_rule'
  tag stig_id: 'RHEL-08-010152'
  tag fix_id: 'F-47755r743817_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe service('emergency') do
    its('params.ExecStart') { should include '/usr/lib/systemd/systemd-sulogin-shell emergency' }
  end
end
