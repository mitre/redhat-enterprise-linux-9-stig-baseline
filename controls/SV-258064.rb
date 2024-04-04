control 'SV-258064' do
  title 'RHEL 8 must ensure session control is automatically started at shell
initialization.'
  desc 'Tmux is a terminal multiplexer that enables a number of terminals to be created, accessed, and controlled from a single screen. Red Hat endorses tmux as the recommended session controlling package.'
  desc 'check', 'Verify the operating system shell initialization file is configured to start each shell with the tmux terminal multiplexer with the following commands:

Determine if tmux is currently running:
     $ sudo ps all | grep tmux | grep -v grep

If the command does not produce output, this is a finding.

Determine the location of the tmux script:
     $ sudo grep -r tmux /etc/bashrc /etc/profile.d

     /etc/profile.d/tmux.sh:  case "$name" in (sshd|login) tmux ;; esac

Review the tmux script by using the following example:
     $ sudo cat /etc/profile.d/tmux.sh

if [ "$PS1" ]; then
parent=$(ps -o ppid= -p $$)
name=$(ps -o comm= -p $parent)
case "$name" in (sshd|login) tmux ;; esac
fi

If "tmux" is not configured as the example above, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure the operating system to initialize the tmux terminal multiplexer as each shell is called by adding the following lines to a custom.sh shell script in the /etc/profile.d/ directory:

if [ "$PS1" ]; then
parent=$(ps -o ppid= -p $$)
name=$(ps -o comm= -p $parent)
case "$name" in (sshd|login) tmux ;; esac
fi

This setting will take effect at next logon.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag gid: 'V-230349'
  tag rid: 'SV-258064r917920_rule'
  tag stig_id: 'RHEL-08-020041'
  tag fix_id: 'F-32993r880735_fix'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  tmux_running = command('ps all | grep tmux | grep -v grep').stdout.strip

  describe 'tmux' do
    it 'should be running' do
      expect(tmux_running).to_not be_empty, 'tmux is not running'
    end
  end

  if tmux_running.nil?

    # compare the tmux config with the expected multiline string the same way we do the banner checks
    # i.e. strip out all whitespace and compare the strings

    expected_config = "if [ \"$PS1\" ]; then\nparent=$(ps -o ppid= -p $$)\nname=$(ps -o comm= -p $parent)\ncase \"$name\" in (sshd|login) tmux ;; esac\nfi".content.gsub(/[\r\n\s]/, '')

    tmux_script = command('grep -r tmux /etc/bashrc /etc/profile.d').stdout.strip.match(/^(?<path>\S+):/)['path']
    tmux_config = file(tmux_script).content.gsub(/[\r\n\s]/, '')

    describe 'tmux' do
      it 'should be configured as expected' do
        expect(tmux_config).to match(/#{expected_config}/), 'tmux config does not match expected script'
      end
    end
  end
end
