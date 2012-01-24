# CREATED BY: RYAN BREED <opensource@breed.org>
# CREATED:    1/21/12

# :title: DnsMessage
# This class wraps the dnsjava Message class and provides methods for turning the message
# into a hash structure with question/answer sections

class DnsMessage
  attr_accessor :frame
  attr_reader :message

  #
  # :args: :frame
  # :yields: self
  #
  def initialize(*args)
    Hash[*args].each { |k, v| self.send("%s=" % k, v) }
    raise ArgumentError if frame.nil?
    @message=Message.new(frame.udp_data.to_java_bytes)
    yield self if block_given?
  end

  # transforms a message instance into a hash and returns it
  def to_h
    # base message structure has questions and an IP frame with it
    h={
      :question=>true,
      :questions=>[],
      :txid=>message.get_header.get_id
    }

    # collects ip frame attributes and sets a hash key under the base hash
    %w{ ip_src ip_dst udp_sport udp_dport ip_ttl time}.each {|attr| h[attr.to_sym]=frame.send(attr)}

    # loop over question section and push each question into the array hash[:questions]
    message.get_section_array(Section::QUESTION).each do |q|
       h[:questions].push({
       :qname=>q.get_name.to_string,
       :qtype=>Type.string(q.get_type),
       :qclass=>DClass.string(q.get_dclass)
       })
    end

    # only process the answers id this is NOT a query packet
    if message.get_header.get_flag(Flags::QR)
      h[:question]=false
      h[:answers]=[]
      message.get_section_array(Section::ANSWER).each do |a|
        h[:answers].push({
          :rr_name=>a.get_name.to_string,
          :rr_type=>Type.string(a.get_type),
          :rr_class=>DClass.string(a.get_dclass),
          :rr_ttl  =>a.get_ttl,
          :rdata=>a.rdata_to_string
                        })
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