control 'SV-258052' do
  title 'All RHEL 9 local interactive user home directories defined in the /etc/passwd file must exist.'
  desc 'If a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon logon. This could create a denial of service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access.'
  desc 'check', "Verify the assigned home directories of all interactive users on the system exist with the following command:

$ sudo pwck -r 

user 'mailnull': directory 'var/spool/mqueue' does not exist

The output should not return any interactive users.

If users home directory does not exist, this is a finding."
  desc 'fix', 'Create home directories to all local interactive users that currently do not have a home directory assigned. Use the following commands to create the user home directory assigned in "/etc/ passwd":

Note: The example will be for the user wadea, who has a home directory of "/home/wadea", a user identifier (UID) of "wadea", and a Group Identifier (GID) of "users assigned" in "/etc/passwd".

$ sudo mkdir /home/wadea 
$ sudo chown wadea /home/wadea
$ sudo chgrp users /home/wadea
$ sudo chmod 0750 /home/wadea'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258052'
  tag rid: 'SV-258052r926143_rule'
  tag stig_id: 'RHEL-09-411065'
  tag fix_id: 'F-61717r926142_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  exempt_home_users = input('exempt_home_users')
  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  iuser_entries = passwd.where { uid.to_i >= uid_min && shell !~ /nologin/ && !exempt_home_users.include?(user) }

  if !iuser_entries.users.nil? && !iuser_entries.users.empty?
    failing_homedirs = iuser_entries.homes.reject { |home|
      file(home).exist?
    }
    describe 'All non-exempt interactive user account home directories on the system' do
      it 'should exist' do
        expect(failing_homedirs).to be_empty, "Failing home directories:\n\t- #{failing_homedirs.join("\n\t- ")}"
      end
    end
  else
    describe 'No non-exempt interactive user accounts' do
      it 'were detected on the system' do
        expect(true).to eq(true)
      end
    end
  end
end
