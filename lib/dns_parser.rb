require 'dnsruby'
require 'ffi/pcap'
require 'mongo'
require 'bit-struct'
require 'pp'

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

class DnsParser
  attr_accessor :pcap_filename, :mongo_server, :mongo_port
  attr_reader   :pcap, :connection, :db
  def initialize(*args)
    Hash[*args].each {|k,v| self.send("%s="%k,v)}
    @mongo_server ||= "localhost"
    @mongo_port   ||= 27017
    @connection = Mongo::Connection.new(mongo_server,mongo_port)
    @db=connection['nominalyze']
    @pcap=FFI::PCap::Offline.new(pcap_filename)
    pcap.setfilter("udp port 53")
    yield self if block_given?
  end
  def parse
    count=0
    pcap.loop do |this,pkt|
      udp=UdpFrame.new(pkt.body)
      pkt_id=db['packets'].insert(udp.to_h.merge(:timestamp=>pkt.timestamp.utc))
      begin
        message=Dnsruby::Message.decode(udp.udp_data)
      rescue
      end
    end
  end
end
