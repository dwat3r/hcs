{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.IP where
--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Control.Monad(replicateM)
import Data.Bits(testBit,shiftR,shiftL,(.|.),(.&.),complement)
import Data.List(foldl')
import Packet.Packet
import qualified Packet.Ethernet as E
--representation:
--fields smaller than a byte stores values as big endian
data IP = IP 	{_version 	:: Word8
        	  	,_hlen 		:: Word8
        		,_tos 		:: Word8
        		,_len 		:: Word16
        		,_ipID 		:: Word16
        		,_flags 	:: Word8
        		,_offset 	:: Word16
        		,_ttl 		:: Word8
        		,_protocol 	:: Word8
        		,_checksum 	:: Word16
        		,_source 	:: IPAddr
        		,_dest 		:: IPAddr
        		,_options 	:: B.ByteString}

--lens magic
makeLenses ''IP
--special flags access:
--stored big endian: rsv,df,mf,0,0....
rsv :: Word8 -> Int
rsv f | testBit f 7 = 1
	  | otherwise = 0
df :: Word8 -> Int
df f | testBit f 6 = 1
	 | otherwise = 0
mf :: Word8 -> Int
mf f | testBit f 5 = 1
	 | otherwise = 0

instance Show IP where
	show i = unlines ["<IP>",
			"version: " ++ show (i^.version),
			"header length: " ++ show (i^.hlen),
			"type of service: " ++ show (i^.tos),
			"total length: " ++ show (i^.len),
			"identification: " ++ show (i^.ipID),
			"flags: ",
			"\treserved: " ++ show (i^.flags & rsv),
			"\tdon't fragment: " ++ show (i^.flags & df),
			"\tmore fragments: " ++ show (i^.flags & mf),
			"fragment offset: " ++ show (i^.offset),
			"protocol: " ++ show (i^.protocol),
			"checksum: " ++ hex (i^.checksum),
			"source :" ++ show (i^.source),
			"destination: " ++ show (i^.dest),
			"options field: " ++ show (i^.options)]

--internal packer,unpacker for [version,hlen] field:
packvh::Word8->Word8->Word8
packvh v h = v .|. (h `shiftR` 4)
unpackvh::Word8->(Word8,Word8)
unpackvh vh = (vh .&. 15,vh `shiftL` 4)
--internal packer,unpacker for [flags,offset] field:
packfo::Word8->Word16->Word16
packfo f o = (fromIntegral f `shiftL` 8) .|. (o `shiftR` 3)
unpackfo::Word16->(Word8,Word16)
unpackfo fo = (fromIntegral fo `shiftR` 8,fo `shiftL` 3)
--helper for calculating options field length:
--hlen->number of Word8 -s
oplen h | h<=5 = 0
		| True = (h-5)*4
--calculating the checksum field:
calcChecksum::IP->IP
calcChecksum ip = ip & checksum .~ (ip & calc)
	where 
		calc::IP->Word16
		calc ip = complement $ foldl' (+) 0 ws
		ws::[Word16]
		ws = runGet (replicateM (10+(ip^.hlen & fromIntegral & oplen)`div`2) gW16) $ toBytes (ip & checksum .~ 0)
--calculating the hlen field:
calcHlen::IP->IP
calcHlen ip = ip & hlen .~ (toBytes ip & B.length & fromIntegral & (`div` 4))
--helper for getting eth+ip header length
eihlen::B.ByteString->Word8
eihlen = snd . unpackvh . B.head . B.drop 14

instance Header IP where
	toBytes i = runPut $ do
		packvh (i^.version) (i^.hlen) & pW8
		i^.tos & pW8
		i^.len & pW16
		i^.ipID & pW16
		packfo (i^.flags) (i^.offset) & pW16
		i^.ttl & pW8
		i^.protocol & pW8
		i^.checksum & pW16
		i^.source & unIpa & pW32
		i^.dest & unIpa & pW32
		i^.options & pB
	fromBytes = runGet $ do
		vh <- gW8
		tos <- gW8
		len <- gW16
		ipID <- gW16
		fo <- gW16
		ttl <- gW8
		protocol <- gW8
		checksum <- gW16
		source <- gW32
		dest <- gW32
		options <- gB (fromIntegral $ oplen $ snd $ unpackvh vh)
		return $ IP (fst $ unpackvh vh)
					(snd $ unpackvh vh)
					tos len ipID
					(fst $ unpackfo fo)
					(snd $ unpackfo fo)
					ttl protocol checksum
					(ipa source)
					(ipa dest)
					options

instance Header (E.Ethernet :+: IP) where
	toBytes (e :+: i) = toBytes e `B.append` toBytes i
	fromBytes bs = 	(fromBytes (B.take 14 bs)::E.Ethernet) :+:
					(fromBytes (B.drop 14 bs)::IP)

instance Attachable E.Ethernet IP where
	e +++ i = (e & E.ethType .~ 0x800) :+: i

ip = IP 4 5 8 20 0 0 0 64 0 0
	(read "0.0.0.0"::IPAddr)
	(read "0.0.0.0"::IPAddr)
	B.empty & calcChecksum & calcHlen

{-
optional constants and predicates from pcs:
iNADDR_ANY		= 0x00000000	-- 0.0.0.0
iNADDR_NONE		= 0x00000000	-- 0.0.0.0
iNADDR_BROADCAST	= 0xffffffff	-- 255.255.255.255
iNADDR_LOOPBACK		= 0x7f000001	-- 127.0.0.1
iNADDR_UNSPEC_GROUP	= 0xe0000000	-- 224.0.0.0
iNADDR_ALLHOSTS_GROUP	= 0xe0000001	-- 224.0.0.1
iNADDR_ALLRTRS_GROUP	= 0xe0000002	-- 224.0.0.2
iNADDR_DVMRP_GROUP	= 0xe0000004	-- 224.0.0.4
iNADDR_ALLPIM_ROUTERS_GROUP = 0xe000000d	-- 224.0.0.13
iNADDR_ALLRPTS_GROUP	= 0xe0000016	-- 224.0.0.22, IGMPv3
iNADDR_MAX_LOCAL_GROUP	= 0xe00000ff	-- 224.0.0.255

inLinklocal::IPAddr->Bool
...
def IN_LINKLOCAL(i):
    """Return True if the given address is in the 169.254.0.0/16 range."""
    return (((i) & 0xffff0000) == 0xa9fe0000)

def IN_MULTICAST(i):
    """Return True if the given address is in the 224.0.0.0/4 range."""
    return (((i) & 0xf0000000) == 0xe0000000)

def IN_LOCAL_GROUP(i):
    """Return True if the given address is in the 224.0.0.0/24 range."""
    return (((i) & 0xffffff00) == 0xe0000000)

def IN_EXPERIMENTAL(i):
    """Return True if the given address is in the 240.0.0.0/24 range."""
    return (((i) & 0xf0000000) == 0xf0000000)

def IN_PRIVATE(i):
    """Return True if the given address is in any of the 10.0.0.0/8,
       172.16.0.0/16, or 192.168.0.0/24 ranges from RFC 1918."""
    return ((((i) & 0xff000000) == 0x0a000000) or \
            (((i) & 0xfff00000) == 0xac100000) or \
            (((i) & 0xffff0000) == 0xc0a80000))
-}