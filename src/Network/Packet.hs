{-# LANGUAGE TypeOperators,GADTs,MultiParamTypeClasses,TypeOperators #-}
--exports:
module Network.Packet where

--imports:
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get hiding (getBytes)
import Control.Monad(replicateM)
import Numeric(showHex,readHex)
import Data.List(intercalate,foldl',unfoldr)
import Data.List.Split(splitOn)
import Data.Word(Word8,Word32,Word16)
import Data.Bits(shiftL,shiftR,(.|.),complement)
import Debug.Trace
--class and abstract data definitions:
data a :+: b where 
	(:+:) :: a -> b -> a :+: b

instance (Show a,Show b)=>Show (a :+: b) where
	show (a :+: b) = show a ++ "\n" ++ show b

infixl 6 :+:

--TODO: implement a Zipper here
--getters for :+:
get2::(a:+:b)->(a,b,(),())
get2 (a:+:b) = (a,b,(),())
get3::(a:+:b:+:c)->(a,b,c,())
get3 (a:+:b:+:c) = (a,b,c,())
get4::(a:+:b:+:c:+:d)->(a,b,c,d)
get4 (a:+:b:+:c:+:d) = (a,b,c,d)

infixl 6 +++

class Attachable a b where
	(+++) :: a -> b -> (a :+: b)
	(+++) = (:+:)

class Header a where
	toBytes :: a -> B.ByteString
	fromBytes :: B.ByteString -> a
	fromBytes = runGet getBytes
	getBytes :: Get a
	getBytes = undefined

--mac address 
newtype MACAddr = MACA B.ByteString
	deriving Eq
--internal unpack,pack for parsing:
unMac :: MACAddr -> B.ByteString
unMac (MACA bs) = bs
mac :: B.ByteString -> MACAddr
mac bs = MACA bs
--B.Bytestring -> String --pretty print
instance Show MACAddr where
	show (MACA mac) = intercalate ":" $ map (\x->showHex x "") $ B.unpack mac

hex :: (Show a,Integral a) => a -> String
hex a = "0x" ++ showHex a ""

--String -> B.ByteString --parse and check length
instance Read MACAddr where
	readsPrec _ s 	| (length $ splitOn ":" s) == 6 = [(MACA $ B.pack $ map (\x->fst $ head $ (readHex x::[(Word8,String)])) $ splitOn ":" s,"")]
					| otherwise = error "Invalid format"

--ip address
newtype IPAddr = IPA Word32
	deriving Eq
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
			octets ip = [fromIntegral (ip `shiftR` 24)
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
grB = getRemainingLazyByteString
--for checksum calculating:
bs2check::B.ByteString->Word16
bs2check bs = complement $ foldl' (\x y->if x+y<x || x+y<y then x+y+1 else x+y) 0 $ runGet (replicateM ((fromIntegral $ B.length bs)`div` 2) gW16) bs

--From PLEAC
bin2dec :: [Word8] -> Word8
bin2dec = foldr (\c s -> s * 2 + c) 0 . reverse

dec2bin :: Word8 -> [Word8]
dec2bin = reverse . unfoldr decomp
    where decomp n = if n == 0 then Nothing else Just(n `mod` 2, n `div` 2)
          
--flip byte order of a Word8: (from little endian to big,and vica versa)
flipBO :: Word8->Word8
flipBO = bin2dec . reverse . dec2bin

flipBO32 :: Word32->Word32
flipBO32 = 	fromO . reverse . toO		
	where
		toO :: Word32 -> [Word8]
		toO ip = [fromIntegral (ip `shiftR` 24)
				,fromIntegral (ip `shiftR` 16)
				,fromIntegral (ip `shiftR` 8)
				,fromIntegral ip]
		fromO :: [Word8] -> Word32
		fromO = foldl' (\acc x->(acc `shiftL` 8) .|. fromIntegral x) 0