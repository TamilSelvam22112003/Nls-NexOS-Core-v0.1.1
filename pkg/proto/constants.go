// Code generated from docs/PROTOCOL.md size tables; DO NOT EDIT BY HAND.
package proto

const (
	WireVersion       = 1
	CommonHeaderLen   = 8
	RDRBodyLen        = 130
	RDRSignatureLen   = 64
	RDRLen            = 194
	M1BodyLen         = 120
	M1InitLen         = 128
	M1CookieBodyLen   = 52
	M1CookieLen       = 60
	M2BodyLen         = 244
	M2Len             = 252
	M3BodyLen         = 178
	M3Len             = 186
	M4BodyLen         = 64
	M4Len             = 72
	DataHeaderLen     = 32
	GCMTagLen         = 16
	RekeyBodyLen      = 132
	RekeyPacketLen    = 180
	OuterIPv6HeaderLen = 40
	UDPHeaderLen      = 8
	DataOverheadLen   = 96
	TUNMTU1500        = 1404
	IPv4TCPMSS1500    = 1364
	IPv6TCPMSS1500    = 1344
)

// Each pair of array declarations makes a size mismatch a compile-time error.
var (
	_ [CommonHeaderLen - (1+1+2+2+2)]byte
	_ [(1+1+2+2+2) - CommonHeaderLen]byte
	_ [RDRBodyLen - (1+1+2+16+32+1+1+16+2+8+8+8+1+7+8+16+2)]byte
	_ [(1+1+2+16+32+1+1+16+2+8+8+8+1+7+8+16+2) - RDRBodyLen]byte
	_ [RDRLen - (RDRBodyLen+RDRSignatureLen)]byte
	_ [(RDRBodyLen+RDRSignatureLen) - RDRLen]byte
	_ [M1BodyLen - (100+20)]byte
	_ [(100+20) - M1BodyLen]byte
	_ [M1InitLen - (CommonHeaderLen+M1BodyLen)]byte
	_ [(CommonHeaderLen+M1BodyLen) - M1InitLen]byte
	_ [M1CookieBodyLen - (32+16+4)]byte
	_ [(32+16+4) - M1CookieBodyLen]byte
	_ [M1CookieLen - (CommonHeaderLen+M1CookieBodyLen)]byte
	_ [(CommonHeaderLen+M1CookieBodyLen) - M1CookieLen]byte
	_ [M2BodyLen - (32+32+32+2+80+2+64)]byte
	_ [(32+32+32+2+80+2+64) - M2BodyLen]byte
	_ [M2Len - (CommonHeaderLen+M2BodyLen)]byte
	_ [(CommonHeaderLen+M2BodyLen) - M2Len]byte
	_ [M3BodyLen - (32+2+80+64)]byte
	_ [(32+2+80+64) - M3BodyLen]byte
	_ [M3Len - (CommonHeaderLen+M3BodyLen)]byte
	_ [(CommonHeaderLen+M3BodyLen) - M3Len]byte
	_ [M4BodyLen - (32+32)]byte
	_ [(32+32) - M4BodyLen]byte
	_ [M4Len - (CommonHeaderLen+M4BodyLen)]byte
	_ [(CommonHeaderLen+M4BodyLen) - M4Len]byte
	_ [DataHeaderLen - (1+1+2+4+16+8)]byte
	_ [(1+1+2+4+16+8) - DataHeaderLen]byte
	_ [RekeyBodyLen - (4+32+32+64)]byte
	_ [(4+32+32+64) - RekeyBodyLen]byte
	_ [RekeyPacketLen - (DataHeaderLen+RekeyBodyLen+GCMTagLen)]byte
	_ [(DataHeaderLen+RekeyBodyLen+GCMTagLen) - RekeyPacketLen]byte
	_ [DataOverheadLen - (OuterIPv6HeaderLen+UDPHeaderLen+DataHeaderLen+GCMTagLen)]byte
	_ [(OuterIPv6HeaderLen+UDPHeaderLen+DataHeaderLen+GCMTagLen) - DataOverheadLen]byte
	_ [TUNMTU1500 - (1500-DataOverheadLen)]byte
	_ [(1500-DataOverheadLen) - TUNMTU1500]byte
	_ [IPv4TCPMSS1500 - (TUNMTU1500-20-20)]byte
	_ [(TUNMTU1500-20-20) - IPv4TCPMSS1500]byte
	_ [IPv6TCPMSS1500 - (TUNMTU1500-40-20)]byte
	_ [(TUNMTU1500-40-20) - IPv6TCPMSS1500]byte
)
