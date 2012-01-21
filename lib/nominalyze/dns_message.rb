# CREATED BY: RYAN BREED <opensource@breed.org>
# CREATED:    1/21/12

class DnsMessage
  attr_accessor :frame
  attr_reader :message
  def initialize(*args)
    Hash[*args].each { |k, v| self.send("%s=" % k, v) }
    raise ArgumentError if frame.nil?
    @message=Message.new(frame.udp_data.to_java_bytes)
  end
  def to_h
    h={
      :question=>true,
      :questions=>[],
      :txid=>message.get_header.get_id
    }
    %w{ip_src ip_dst udp_sport udp_dport ip_ttl udp_data}.each {|attr| h[attr.to_sym]=frame.send(attr)}
    message.get_section_array(Section::QUESTION).each do |q|
      h[:questions].push({:name=>q.get_name.to_string, :type=>Type.string(q.get_type)})
    end
    if message.get_header.get_flag(Flags::QR)
      h[:question]=false
      h[:answers]=[]
      message.get_section_array(Section::ANSWER).each do |a|
        h[:answers].push({:name=>a.get_name.to_string,:type=>Type.string(a.get_type),:rdata=>a.rdata_to_string})
      end
    end
    h
  end
  # TODO: messy messy messy  - if i don't respond to this message, try UdpFrame and then Java::OrgXBillDNS::Message
  def method_missing(meth,*args)
    if frame.respond_to? meth
      frame.send(meth,*args)
    elsif message.respond_to?(meth)
      message.send(meth,*args)
    else
      raise NoMethodError, "No method #{meth.to_s}"
    end
  end
end