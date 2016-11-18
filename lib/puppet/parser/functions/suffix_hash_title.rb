module Puppet::Parser::Functions
  newfunction(:suffix_hash_title, :type => :rvalue) do |args|
    result = {}
    if args[0].class == Hash and args[1].class == String
      args[0].each do |title, values|
        result[title + args[1]] = values
      end
    end
    return result
  end
end
