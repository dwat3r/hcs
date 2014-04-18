{-# LANGUAGE TypeOperators,GADTs,MultiParamTypeClasses,TypeOperators #-}
--exports:
module Packet.Packet where

--imports:
import qualified Data.ByteString.Lazy as B
import Numeric(showHex)
import Data.List(intercalate)
import Data.List.Split(splitOn)
import Data.Word(Word8)
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
--B.Bytestring -> String --pretty print
instance Show MACAddr where
	show (MACA mac) = intercalate ":" $ map hex $ B.unpack mac
		where 
			hex :: (Show a,Integral a) => a -> String
			hex a = showHex a ""
--String -> B.ByteString --parse and check length
instance Read MACAddr where
	readsPrec _ s 	| (length $ splitOn ":" s) == 6 = [(MACA $ B.pack $ map (\x->read x::Word8) $ splitOn ":" s,"")]
					| otherwise = error "Invalid format"


--ip address
newtype IPAddr = IPA Word32
--Word32 -> String
instance Show IPAddr where
	show (IPA ip) = undefined
--String -> Word32
instance Read IPAddr where
	readsPrec _ s | (length $ splitOn "." s) == 4 = [(IPA $ {-bit magic-},"")]