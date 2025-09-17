class Gsettings < Inspec.resource(1)
  name 'gsettings'

  supports platform: 'redhat', release: '9.*'

  desc 'Use the gsettings InSpec audit resource to test configuration data saved in GNOME\'s GSettings format.'

  example <<~EXAMPLE
    describe gsettings('disable-restart-buttons', 'org.gnome.login-screen')
      it { should exist }
      it { should be_set('true') }
      it { should be_locked }
    end
  EXAMPLE

  def initialize(key, schema, schemadir = nil)
    @key = key
    @schema = schema
    @schemadir = schemadir
    @schemadir_snippet = schemadir == nil ? '' : " --schemadir #{@schemadir}"
  end

  def get()
    @get ||= inspec.command("gsettings#{@schemadir_snippet} get #{@schema} #{@key}")
  end

  def writable()
    @writable ||= inspec.command("gsettings#{@schemadir_snippet} writable #{@schema} #{@key}")
  end

  def exist?()
    get.stderr.strip.empty?
  end

  def set?(value)
    get.stdout.strip == "#{value}"
  end

  def locked?()
    writable.stdout.strip == 'false'
  end

  def to_s
    "gsettings#{@schemadir == nil ? '' : "(#{@schemadir})"} #{@schema} #{@key}"
  end
end
