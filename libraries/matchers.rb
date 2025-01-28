
RSpec::Matchers.define :match_pam_rule do |expected|
  match do |actual|
    @expected = expected.to_s
    actual_munge = {}
    retval = initialize_retval

    validate_operator if integer_arg?

    if @args_type
      actual.services.each do |service|
        expected_line = Pam::Rule.new(expected, { service_name: service })
        potentials = actual.find_all { |line| line.match?(expected_line) }
        next unless potentials.any?

        actual_munge[service] ||= []
        actual_munge[service] += potentials.map(&:to_s)
        retval = process_potentials(potentials, retval)
      end
    else
      retval = actual.include?(expected, { service_name: actual.service })
    end

    @actual = format_actual(actual_munge)
    retval
  end

  diffable

  chain :any_with_args do |args|
    @args_type = :any_with_args
    @args = args
  end

  chain :all_with_args do |args|
    @args_type = :all_with_args
    @args = args
  end

  chain :all_without_args do |args|
    @args_type = :all_without_args
    @args = args
  end

  chain :all_with_integer_arg do |key, op, value|
    @args_type = :all_with_integer_arg
    @args = { key: key, operator: op, value: value }
  end

  chain :any_with_integer_arg do |key, op, value|
    @args_type = :any_with_integer_arg
    @args = { key: key, operator: op, value: value }
  end

  description do
    "include #{expected}" + args_description
  end

  private

  def initialize_retval
    case @args_type
    when :all_with_args, :all_without_args, :all_with_integer_arg
      true
    when :any_with_args, :any_with_integer_arg
      false
    end
  end

  def integer_arg?
    %i[all_with_integer_arg any_with_integer_arg].include?(@args_type)
  end

  def validate_operator
    return if @args.is_a?(Hash) && Numeric.method_defined?(@args[:operator])

    raise("Error: Operator '#{@args[:operator]}' is an invalid numeric comparison operator.")
  end

  def process_potentials(potentials, retval)
    potentials.each do |potential|
      case @args_type
      when :all_without_args, :all_with_args
        retval = potential.module_arguments.join(" ").match?(@args)
      when :all_with_integer_arg, :any_with_integer_arg
        retval = matching_integer_arg?(potential)
      end
      break unless retval
    end
    retval
  end

  def matching_integer_arg?(line)
    line.module_arguments.any? do |arg|
      key, value = arg.split("=")
      value && (@args[:key] == key) && value.match?(/^-?\d+$/) && value.to_i.send(@args[:operator].to_sym, @args[:value])
    end
  end

  def format_actual(actual_munge)
    return actual.to_s if actual_munge.empty?

    actual_munge.one? ? actual_munge.values.flatten.join("\n") : format_multiple_services(actual_munge)
  end

  def format_multiple_services(actual_munge)
    actual_munge.map { |service, lines| lines.map { |line| "#{service} #{line}" } }.flatten.join("\n")
  end

  def args_description
    return "" unless @args_type

    case @args_type
    when :all_with_args, :any_with_args
      ", #{@args_type.to_s.gsub("_", " ")} #{@args}"
    when :all_without_args
      ", all without args #{@args}"
    when :all_with_integer_arg, :any_with_integer_arg
      ", #{@args_type.to_s.gsub("_", " ")} #{@args[:key]} #{@args[:operator]} #{@args[:value]}"
    end
  end
end

RSpec::Matchers.define :match_pam_rules do |expected|
  match do |actual|
    @expected = expected.to_s
    @actual = actual.to_s
    @exactly ? actual.include_exactly?(expected) : actual.include?(expected)
  end

  diffable

  chain :exactly do
    @exactly = true
  end

  description do
    "include #{expected}" + (@exactly ? " exactly" : "")
  end
end
