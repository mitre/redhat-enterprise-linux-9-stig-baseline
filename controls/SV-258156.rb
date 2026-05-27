control 'SV-258156' do
  title 'RHEL 9 must take action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.'
  desc "If security personnel are not notified immediately when storage volume reaches a maximum of 75 percent utilization, they are unable to plan for audit record storage capacity expansion. The notification can be set to trigger at lower utilization thresholds at the information system security officer's (ISSO's) discretion."
  desc 'check', 'Verify RHEL 9 takes action when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity with the following command:

$ sudo grep -w space_left /etc/audit/auditd.conf

space_left = 25%

If the value of the "space_left" keyword is not set to 25 percent or greater of the storage volume allocated to audit logs, or if the line is commented out, ask the system administrator (SA) to indicate how the system is providing real-time alerts to the SA and ISSO. If the "space_left" value is not configured to the value 25 percent or more, this is a finding.'
  desc 'fix', 'Configure RHEL 9 to initiate an action to notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches (at most) 75 percent of the repository maximum audit record storage capacity by adding/modifying the following line in the /etc/audit/auditd.conf file.

space_left  = 25%'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag gid: 'V-258156'
  tag rid: 'SV-258156r1106364_rule'
  tag stig_id: 'RHEL-09-653035'
  tag fix_id: 'F-61821r1102076_fix'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternative_logging_method') == ''
    describe auditd_conf do
      its('space_left.to_i') { should cmp >= input('audit_storage_threshold') }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
