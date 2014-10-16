-- Joakim Carlsson: 2014-10-08
local cloudmac = Proto("CloudMAC", "CloudMAC Header")
local cloudmac_dst = ProtoField.new("Destination", "cloudmac.dst", ftypes.ETHER)
local cloudmac_signal = ProtoField.new("Signal Strength", "cloudmac.signal", ftypes.UINT8)
local cloudmac_rate = ProtoField.new("Data Rate", "cloudmac.rate", ftypes.UINT8)
local cloudmac_src = ProtoField.new("VAP Identification", "cloudmac.src", ftypes.ETHER)
local CLOUDMAC_DST_LEN = 6
local CLOUDMAC_SIGNAL_LEN = 1
local CLOUDMAC_RATE_LEN = 1
local CLOUDMAC_SOURCE_LEN = 4
local CLOUDMAC_TYPE_LEN = 2
local CLOUDMAC_TYPE_OFFSET = CLOUDMAC_DST_LEN + CLOUDMAC_SIGNAL_LEN + CLOUDMAC_RATE_LEN + CLOUDMAC_SOURCE_LEN
local CLOUDMAC_HEADER_LEN = CLOUDMAC_DST_LEN + CLOUDMAC_SIGNAL_LEN + CLOUDMAC_RATE_LEN + CLOUDMAC_SOURCE_LEN + CLOUDMAC_TYPE_LEN
local RADIOTAP_MIN_LEN = 8
local RADIOTAP_LEN_OFFSET = 2
local RADIOTAP_LEN_LEN = 2
local CLOUDMAC_MIN_LEN = CLOUDMAC_HEADER_LEN + RADIOTAP_MIN_LEN + 1

cloudmac.fields = { cloudmac_dst, cloudmac_signal, cloudmac_rate, cloudmac_src }

function tvbToUint(tvb, i, len)
	return tvb:range(i, len):uint()
end

function cloudmac.dissector(tvbuf, pktinfo, root)
	local pktlen = tvbuf:reported_length_remaining()
	local tree = root:add(cloudmac, tvbuf:range(0, CLOUDMAC_HEADER_LEN))	
	local radiotap = Dissector.get("radiotap")
	
	if pktlen < CLOUDMAC_MIN_LEN then
		tree:add_proto_expert_info(ef_too_short)
		return 
	end	

	-- CloudMAC Fields:
	local source_mac = ByteArray.new("0000" .. tostring(tvbuf:range(8, 4)))

	tree:add(cloudmac_dst, tvbuf:range(0, 6))
	tree:add(cloudmac_signal, tvbuf:range(6, 1)):append_text(" dBm")
	tree:add(cloudmac_rate, tvbuf:range(7,1), tvbToUint(tvbuf, 7, 1) * 500 / 1000):append_text(" Mb/s")
	tree:add(cloudmac_src, ByteArray.tvb(source_mac, "source"):range(0, 6))
	
	local radiotap_offset = CLOUDMAC_HEADER_LEN
	local radiotap_len = tvbuf:range(CLOUDMAC_HEADER_LEN + RADIOTAP_LEN_OFFSET, RADIOTAP_LEN_LEN):le_uint()
	local wlan_offset = radiotap_offset + radiotap_len
	local wlan_length = pktlen - wlan_offset
	
	-- Radiotap & 802.11:
	-- Radiotap willt ake care of the 802.11 frame for us.
	radiotap:call(tvbuf(radiotap_offset, radiotap_len + wlan_length):tvb(), pktinfo, root)
	pktinfo.cols.protocol:set("CloudMAC")
end

local function cloudmac_heur_dissect(tvbuf, pktinfo, root)
	-- Check if the packet is a CloudMAC packet.
	local pktlen = tvbuf:reported_length_remaining()

	if pktlen < CLOUDMAC_MIN_LEN then
		return false
	end

	if tostring(tvbuf:range(CLOUDMAC_TYPE_OFFSET, CLOUDMAC_TYPE_LEN)) ~= "1337" then
		return false
	end

	cloudmac.dissector(tvbuf, pktinfo, root)

	pktinfo.conversation = cloudmac

	return true
end

cloudmac:register_heuristic("eth", cloudmac_heur_dissect)
