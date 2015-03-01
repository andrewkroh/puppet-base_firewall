Facter.add(:ip6tables_input_policy) do
  confine :kernel => :linux
  setcode do
    input = Facter::Util::Resolution.exec('ip6tables -L INPUT')
    if input 
      input.match(/^chain.+policy\s+(\w+)/i)[1]
    else
      nil
    end
  end
end

Facter.add(:ip6tables_output_policy) do
  confine :kernel => :linux
  setcode do
    output = Facter::Util::Resolution.exec('ip6tables -L OUTPUT')
    if output
      output.match(/^chain.+policy\s+(\w+)/i)[1]
    else
      nil
    end
  end
end

Facter.add(:ip6tables_forward_policy) do
  confine :kernel => :linux
  setcode do
    forward = Facter::Util::Resolution.exec('ip6tables -L FORWARD')
    if forward
      forward.match(/^chain.+policy\s+(\w+)/i)[1]
    else
      nil
    end
  end
end
