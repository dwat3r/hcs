{-# LANGUAGE TemplateHaskell,TypeOperators,MultiParamTypeClasses,FlexibleInstances #-}
module Packet.IP where
--imports:
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Data.Bits(testBit,shiftR,shiftL,(.|.),(.&.))
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
			"header length: " ++ show (i^.len),
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
hlen' h | h<=5 = 0
		| True = (h-5)*8
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
	fromBytes bs = runGet (do
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
		options <- gB (fromIntegral $ hlen' $ snd $ unpackvh vh)
		return $ IP (fst $ unpackvh vh)
					(snd $ unpackvh vh)
					tos len ipID
					(fst $ unpackfo fo)
					(snd $ unpackfo fo)
					ttl protocol checksum
					(ipa source)
					(ipa dest)
					options) bs

instance Header (E.Ethernet :+: IP) where
	toBytes (e :+: i) = undefined
	fromBytes bs = undefined
instance Attachable E.Ethernet IP where


ip = IP