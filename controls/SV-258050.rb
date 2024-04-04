control 'SV-258050' do
  title 'Executable search paths within the initialization files of all local interactive RHEL 9 users must only contain paths that resolve to the system default or the users home directory.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory (other than the users home directory), executables in these directories may be executed instead of system commands.

This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. If deviations from the default system search path for the local interactive user are required, they must be documented with the information system security officer (ISSO).'
  desc 'check', 'Verify that all local interactive user initialization file executable search path statements do not contain statements that will reference a working directory other than user home directories with the following commands:

$ sudo grep -i path= /home/*/.*

/home/[localinteractiveuser]/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin

If any local interactive user initialization files have executable search path statements that include directories outside of their home directory and is not documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Edit the local interactive user initialization files to change any PATH
variable statements that reference directories other than their home directory.

    If a local interactive user requires path variables to reference a
directory owned by the application, it must be documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 9'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-258050'
  tag rid: 'SV-258050r926137_rule'
  tag stig_id: 'RHEL-09-411055'
  tag fix_id: 'F-61715r926136_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  ignore_shells = input('non_interactive_shells').join('|')

  findings = {}
  users.where { !shell.match(ignore_shells) && (uid >= 1000 || uid.zero?) }.entries.each do |user_info|
    next if input('exempt_home_users').include?(user_info.username.to_s)

    grep_results = command("grep -i path= --exclude=\".bash_history\" #{user_info.home}/.*").stdout.split("\n")
    grep_results.each do |result|
      result.slice! 'PATH='
      # Case when last value in exec search path is :
      result += ' ' if result[-1] == ':'
      result.slice! '$PATH:'
      result.gsub! '="', '=' # account for cases where path is set to equal a quote-wrapped statement
      result.gsub! '$HOME', user_info.home.to_s
      result.gsub! '~', user_info.home.to_s
      result.gsub! ':$PATH', '' # remove $PATH if it shows up at the end of line
      line_arr = result.split(':')
      line_arr.delete_at(0)
      line_arr.each do |line|
        line = line.strip

        # Don't run test on line that exports PATH and is not commented out
        next unless !line.start_with?('export') && !line.start_with?('#')

        # Case when :: found in exec search path or : found at beginning
        if line.strip.empty?
          curr_work_dir = command('pwd').stdout.delete("\n")
          line = curr_work_dir if curr_work_dir.start_with?(user_info.home.to_s) || curr_work_dir[]
        end

        # catch a leading '"'
        line = line[1..line.length] if line.start_with?('"')

        # This will fail if non-home directory found in path
        next if line.start_with?(user_info.home)

        # we want a hash of usernames as the keys and arrays of failing lines as values
        findings[user_info.username] = if findings[user_info.username]
                                         findings[user_info.username] << line
                                       else
                                         [line]
                                       end
      end
    end
  end

  describe 'Initialization files' do
    it "should not include executable search paths that include directories outside the respective user's home directory" do
      expect(findings).to be_empty, "Users with non-homedir paths assigned to their PATH environment variable:\n\t#{findings}"
    end
  end
end
