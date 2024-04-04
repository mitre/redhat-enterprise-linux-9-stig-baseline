control 'SV-258156' do
  title 'RHEL 8 must take action when allocated audit record storage volume
    reaches 75 percent of the repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately when storage volume
    reaches 75 percent utilization, they are unable to plan for audit record
    storage capacity expansion.'
  desc 'check', 'Verify RHEL 8 takes action when allocated audit record storage
    volume reaches 75 percent of the repository maximum audit record storage
    capacity with the following commands:

        $ sudo grep -w space_left /etc/audit/auditd.conf

        space_left = 25%

    If the value of the "space_left" keyword is not set to "25%" or if the
    line is commented out, ask the System Administrator to indicate how the system
    is providing real-time alerts to the SA and ISSO.

    If there is no evidence that real-time alerts are configured on the system,
    this is a finding.'
  desc 'fix', 'Configure the operating system to initiate an action to notify the
    SA and ISSO (at a minimum) when allocated audit record storage volume reaches
    75 percent of the repository maximum audit record storage capacity by
    adding/modifying the following line in the /etc/audit/auditd.conf file.

    space_left = 25%

    Note: Option names and values in the auditd.conf file are case insensitive.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag gid: 'V-230483'
  tag rid: 'SV-258156r877389_rule'
  tag stig_id: 'RHEL-08-030730'
  tag fix_id: 'F-33127r744013_fix'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternative_logging_method') != ''
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  else
    describe auditd_conf do
      its('space_left.to_i') { should cmp >= input('audit_storage_threshold') }
    end
  end
end
