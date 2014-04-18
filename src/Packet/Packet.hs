{-# LANGUAGE TypeOperators,GADTs,MultiParamTypeClasses,TypeOperators #-}
--exports:
module Packet.Packet where

--imports:
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Numeric(showHex)
import Data.List(intercalate,foldl')
import Data.List.Split(splitOn)
import Data.Word(Word8,Word32)
import Data.Bits(shiftL,shiftR,(.|.))
--class and abstract data definitions:
data a :+: b where 
	(:+:) :: a -> b -> a :+: b

instance (Show a,Show b)=>Show (a :+: b) where
	show (a :+: b) = show a ++ "\n" ++ show b

infixr 7 :+:
--de-concatenation
--TODO: implement a Zipper here
pLeft :: a :+: b -> a
pLeft (a :+: b) = a

pRight :: a :+: b -> b
pRight (a :+: b) = b

infixr +++

class Attachable a b where
	(+++) :: a -> b -> (a :+: b)
	(+++) = (:+:)

class Header a where
	toBytes :: a -> B.ByteString
	fromBytes :: B.ByteString -> a
--mac address 
newtype MACAddr = MACA B.ByteString
--internal unpack,pack for parsing:
unMac :: MACAddr -> B.ByteString
unMac (MACA bs) = bs
mac :: B.ByteString -> MACAddr
mac bs = MACA bs
--B.Bytestring -> String --pretty print
instance Show MACAddr where
	show (MACA mac) = intercalate ":" $ map hex $ B.unpack mac

hex :: (Show a,Integral a) => a -> String
hex a = showHex a ""
--String -> B.ByteString --parse and check length
instance Read MACAddr where
	readsPrec _ s 	| (length $ splitOn ":" s) == 6 = [(MACA $ B.pack $ map (\x->read x::Word8) $ splitOn ":" s,"")]
					| otherwise = error "Invalid format"

--ip address
newtype IPAddr = IPA Word32
--internal unpack,pack for parsing:
unIpa :: IPAddr -> Word32
unIpa (IPA w) = w
ipa :: Word32 -> IPAddr
ipa w = IPA w
--Word32 -> String
instance Show IPAddr where
	show (IPA ip) = intercalate "." $ map show $ octets ip
		where
			octets :: Word32 -> [Word8]
			octets w = 	[fromIntegral (ip `shiftR` 24)
						,fromIntegral (ip `shiftR` 16)
						,fromIntegral (ip `shiftR` 8)
						,fromIntegral ip]
--String -> Word32
instance Read IPAddr where
	readsPrec _ s | (length $ splitOn "." s) == 4 = [(IPA $ toW32 $ map (\x->read x::Word8) $ splitOn "." s,"")]
		where
			toW32 :: [Word8]->Word32
			toW32 = foldl' (\acc x->(acc `shiftL` 8) .|. fromIntegral x) 0

--function synonyms for parsing:
--put:
pW8 = putWord8
pW16 = putWord16be
pW32 = putWord32be
pB = putLazyByteString
--get:
gW8 = getWord8
gW16 = getWord16be
gW32 = getWord32be
gB = getLazyByteString