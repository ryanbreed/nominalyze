require 'java'
require 'mongo'
require 'bit-struct'
require 'ffi-pcap'
require 'pp'
require 'dnsjava-2.1.3.jar'

module JavaImports
  include_package 'org.xbill.DNS'
end
#include JavaImports

class Object
  class << self
    alias :const_missing_old :const_missing
    def const_missing c
      JavaImports.const_get c
    end
  end
end


class UdpFrame <BitStruct
  hex_octets :enet_dst,  48,     "Source MAC"
  hex_octets :enet_src,  48,     "Destination MAC"
  unsigned   :enet_type,16,     "Ethertype or length"
  unsigned    :ip_v,     4,     "Version"
  unsigned    :ip_hl,    4,     "Header length"
  unsigned    :ip_tos,   8,     "TOS"
  unsigned    :ip_len,  16,     "Length"
  unsigned    :ip_id,   16,     "ID"
  unsigned    :ip_off,  16,     "Frag offset"
  unsigned    :ip_ttl,   8,     "TTL"
  unsigned    :ip_p,     8,     "Protocol"
  unsigned    :ip_sum,  16,     "Checksum"
  octets      :ip_src,  32,     "Source addr"
  octets      :ip_dst,  32,     "Dest addr"
  unsigned    :udp_sport,       16,     "Source Port"
  unsigned    :udp_dport,       16,     "Destination Port"
  unsigned    :udp_length,  16,     "Datagram Length"
  unsigned    :udp_checksum,16,     "Datagram Checksum"
  rest        :udp_data,            "UDP Data"
  initial_value.ip_v    = 4
  initial_value.ip_hl   = 5
  alias_method :original_to_h, :to_h

  def to_h
    h=original_to_h
    h[:udp_data]=BSON::Binary.new(h[:udp_data])
    h
  end
end


class DnsMessage
  attr_reader :message, :frame
  def initialize(frame)
    @frame=frame
    @message=Message.new(frame.udp_data.to_java_bytes)
  end
  def to_h
    h={
      :questions=>[],
      :txid=>message.get_header.get_id
    }
    %w{ip_src ip_dst udp_sport udp_dport ip_ttl udp_data}.each {|attr| h[attr.to_sym]=frame.send(attr)}
    message.get_section_array(Section::QUESTION).each do |q|
      h[:questions].push({:name=>q.get_name.to_string, :type=>Type.string(q.get_type)})
    end
    if message.get_header.get_flag(Flags::QR)
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

class DnsParser
  attr_accessor :pcap_filename, :mongo_server, :mongo_port
  attr_reader   :pcap, :connection, :db, :packets
  def initialize(*args)
    Hash[*args].each {|k,v| self.send("%s="%k,v)}
    @mongo_server ||= "localhost"
    @mongo_port   ||= 27017
    @connection = Mongo::Connection.new(mongo_server,mongo_port)
    @db=connection['nominalyze']
    @pcap=FFI::PCap::Offline.new(pcap_filename)
    pcap.setfilter("udp port 53")
    @packets=[]
    @frames=[]
    @messages=[]
    yield self if block_given?
  end

  def parse
    t=Time.new.to_i
    hashes=0
    pcap.loop do |this,pkt|
      message=DnsMessage.new(UdpFrame.new(pkt.body))
      #db["dns"].insert(message)
      hashes+=1
    end
    puts "parsed #{hashes} messages in #{Time.new.to_i - t} seconds"
    nil
  end
end
