# CREATED BY: RYAN BREED <opensource@breed.org>
# CREATED:    1/21/12
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

  attr_accessor :time

  #def to_h
  #  h=original_to_h
  #  h[:udp_data]=BSON::Binary.new(h[:udp_data])
  #  h
  #end
end