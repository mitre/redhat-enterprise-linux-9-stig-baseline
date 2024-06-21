control 'SV-258051' do
  title 'All RHEL 9 local interactive users must have a home directory assigned in the /etc/passwd file.'
  desc 'If local interactive users are not assigned a valid home directory,
there is no place for the storage and control of files they should own.'
  desc 'check', "Verify that interactive users on the system have a home directory assigned with the following command:

$ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd

smithk:x:1000:1000:smithk:/home/smithk:/bin/bash
scsaustin:x:1001:1001:scsaustin:/home/scsaustin:/bin/bash
djohnson:x:1002:1002:djohnson:/home/djohnson:/bin/bash

Inspect the output and verify that all interactive users (normally users with a user identifier (UID) greater that 1000) have a home directory defined.

If users home directory is not defined, this is a finding."
  desc 'fix', 'Create and assign home directories to all local interactive users on RHEL 9 that currently do not have a home directory assigned.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258051'
  tag rid: 'SV-258051r926140_rule'
  tag stig_id: 'RHEL-09-411060'
  tag fix_id: 'F-61716r926139_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  exempt_users = input('home_users_exemptions')
  ignore_shells = input('non_interactive_shells').join('|')
  actvite_users_without_homedir = users.where { !shell.match(ignore_shells) && home.nil? }.entries

  # only_if("This control is Not Applicable since no 'non-exempt' users were found", impact: 0.0) { !active_home.empty? }

  describe 'All non-exempt users' do
    it 'have an assinded home directory that exists' do
      failure_message = "The following users do not have an assigned home directory: #{actvite_users_without_homedir.join(', ')}"
      expect(actvite_users_without_homedir).to be_empty, failure_message
    end
  end
  describe 'Note: `exempt_home_users` skipped user' do
    exempt_users.each do |u|
      next if exempt_users.empty?

      it u.to_s do
        expect(user(u).username).to be_truthy.or be_nil
      end
    end
  end
end
