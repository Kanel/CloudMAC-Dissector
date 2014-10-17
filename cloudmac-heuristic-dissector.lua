-- Written by	| Joakim Carlsson
-- Last changed | 2014-10-17
-- Note 	| Only works on Wireshark 1.11.3 or newer.
--
-- CloudMAC packets can take two different forms depending on if they're inbound or outbound.
--
-- Inbound: Packets that are routed to a VAP.
-------------------------------------------------------------------------
--|                          |                          |               |
--| Destination              | Source                   | Ethernet Type |
--|                          |                          |               |
-------------------------------------------------------------------------
--| 6 bytes                  | 6 Bytes                  | 2 Bytes       |
-------------------------------------------------------------------------
--
-- Outbound: Packets that are routed from a VAP.
-------------------------------------------------------------------------
--|             |         |        |                    |               |
--| Destination | Signal  | Rate   | VAP Identification | Ethernet Type |
--|             |         |        |                    |               |
-------------------------------------------------------------------------
--| 6 bytes     | 1 Byte  | 1 Byte | 4 Bytes            | 2 Bytes       |
-------------------------------------------------------------------------
--
-- Fields:
-- | Destination: MAC address of the receiver.
-- | Source: MAC Address of the sender.
-- | Signal: Received signal strength in dBm. The intention being that the transmission power should conform to this value rather than the Radiotap headers value.
-- | Rate: Transmission rate in units of 100 Kbps; a value of 108 would mean 54 Mbps. The intention is to be able to manipulate the transmission rate of traffic by directly changing this value.
-- | VAP Identification: The identity of the access point handling this traffic; the last four bytes of access points MAC address.
-- | Ethernet Type: The Ethernet type for CloudMAC packets; it's value is 0x1337 (4919).

local cloudmac = Proto("CloudMAC", "CloudMAC Header")
local cloudmac_dst = ProtoField.new("Destination", "cloudmac.dst", ftypes.ETHER)
local cloudmac_src = ProtoField.new("Source", "cloudmac.source", ftypes.ETHER)
local cloudmac_ethertype = ProtoField.new("Ethernet Type", "cloudmac.ethertype", ftypes.UINT16)
local cloudmac_signal = ProtoField.new("Signal Strength", "cloudmac.signal", ftypes.UINT8)
local cloudmac_rate = ProtoField.new("Data Rate", "cloudmac.rate", ftypes.UINT8)
local cloudmac_vapid = ProtoField.new("VAP Identification", "cloudmac.vapid", ftypes.STRING)

-- I want to read these values later.
local ieee802_11_bssid_f = Field.new("wlan.bssid")
local ieee802_11_source_f = Field.new("wlan.sa")

-- Information about fields.
local CLOUDMAC_DST_OFFSET = 0
local CLOUDMAC_DST_LEN = 6
local CLOUDMAC_SRC_OFFSET = 6
local CLOUDMAC_SRC_LEN = 6
local CLOUDMAC_SIGNAL_OFFSET = 6
local CLOUDMAC_SIGNAL_LEN = 1
local CLOUDMAC_RATE_OFFSET = 7
local CLOUDMAC_RATE_LEN = 1
local CLOUDMAC_VAPID_OFFSET = 8
local CLOUDMAC_VAPID_LEN = 4
local CLOUDMAC_ETHERTYPE_OFFSET = 12
local CLOUDMAC_ETHERTYPE_LEN = 2
local CLOUDMAC_HEADER_LEN = 14
local RADIOTAP_OFFSET = CLOUDMAC_HEADER_LEN
local RADIOTAP_MIN_LEN = 8
local RADIOTAP_LEN_OFFSET = 2
local RADIOTAP_LEN_LEN = 2
local CLOUDMAC_MIN_LEN = CLOUDMAC_HEADER_LEN + RADIOTAP_MIN_LEN + 1

-- Add fields.
cloudmac.fields = { cloudmac_dst, cloudmac_src, cloudmac_ethertype, cloudmac_signal, cloudmac_rate, cloudmac_vapid }

function cloudmac.dissector(tvbuf, pktinfo, root)
	local pktlen = tvbuf:reported_length_remaining()
	local tree = root:add(cloudmac, tvbuf:range(0, CLOUDMAC_HEADER_LEN))	
	local radiotap = Dissector.get("radiotap")
	
	if pktlen < CLOUDMAC_MIN_LEN then
		tree:add_proto_expert_info(ef_too_short)
		return 
	end
	
	-- Radiotap & 802.11:
	-- Radiotap will take care of the 802.11 frame for us.
	radiotap:call(tvbuf(RADIOTAP_OFFSET, pktlen - RADIOTAP_OFFSET):tvb(), pktinfo, root)
	
	-- CloudMAC Fields:
	local ieee802_11_bssid = ieee802_11_bssid_f()
	local ieee802_11_source = ieee802_11_source_f()
	
	-- CloudMAC can take two different forms.
	if ieee802_11_source == ieee802_11_bssid then
		-- Inbound frame.
		tree:add(cloudmac_dst, tvbuf:range(CLOUDMAC_DST_OFFSET, CLOUDMAC_DST_LEN))
		tree:add(cloudmac_src, tvbuf:range(CLOUDMAC_SRC_OFFSET, CLOUDMAC_SRC_LEN))
		tree:add(cloudmac_ethertype, tvbuf:range(CLOUDMAC_ETHERTYPE_OFFSET, CLOUDMAC_ETHERTYPE_LEN))		
		tree:set_text("CloudMAC, Inbound Frame")
	else 
		-- Outbound frame.
		local rate_mbps = tvbuf:range(CLOUDMAC_RATE_OFFSET, CLOUDMAC_RATE_LEN):uint() * 0.5;
		local vapid_0 = tvbuf:range(CLOUDMAC_VAPID_OFFSET + 0, 1)
		local vapid_1 = tvbuf:range(CLOUDMAC_VAPID_OFFSET + 1, 1)
		local vapid_2 = tvbuf:range(CLOUDMAC_VAPID_OFFSET + 2, 1)
		local vapid_3 = tvbuf:range(CLOUDMAC_VAPID_OFFSET + 3, 1)
		local vapid = tostring(vapid_0) .. ":" .. tostring(vapid_1) .. ":" .. tostring(vapid_2) .. ":" .. tostring(vapid_3)
	
		tree:add(cloudmac_dst, tvbuf:range(CLOUDMAC_DST_OFFSET, CLOUDMAC_DST_LEN))
		tree:add(cloudmac_signal, tvbuf:range(CLOUDMAC_SIGNAL_OFFSET, CLOUDMAC_SIGNAL_LEN)):append_text(" dBm")
		tree:add(cloudmac_rate, tvbuf:range(CLOUDMAC_RATE_OFFSET, CLOUDMAC_RATE_LEN), rate_mbps):append_text(" Mb/s")
		tree:add(cloudmac_vapid, tvbuf:range(CLOUDMAC_VAPID_OFFSET, CLOUDMAC_VAPID_LEN), vapid)
		tree:add(cloudmac_ethertype, tvbuf:range(CLOUDMAC_ETHERTYPE_OFFSET, CLOUDMAC_ETHERTYPE_LEN))
		tree:set_text("CloudMAC, Outbound Frame")
	end
	
	pktinfo.cols.protocol:set("CloudMAC")
end

-- Check if the packet is a CloudMAC packet.
local function cloudmac_heur_dissect(tvbuf, pktinfo, root)
	local pktlen = tvbuf:reported_length_remaining()

	if pktlen < CLOUDMAC_MIN_LEN then
		return false
	end

	if tostring(tvbuf:range(CLOUDMAC_ETHERTYPE_OFFSET, CLOUDMAC_ETHERTYPE_LEN)) ~= "1337" then
		return false
	end

	cloudmac.dissector(tvbuf, pktinfo, root)

	pktinfo.conversation = cloudmac

	return true
end

-- Register to dissect ethernet packets.
cloudmac:register_heuristic("eth", cloudmac_heur_dissect)
