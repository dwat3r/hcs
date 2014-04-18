{-# LANGUAGE TypeOperators,GADTs,MultiParamTypeClasses,TypeOperators #-}
--exports:
module Packet.Packet where

--imports:
import qualified Data.ByteString.Lazy as B
import Numeric(showHex)
import Data.List(intercalate)
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
--mac adress 
fromMac :: B.ByteString -> String
fromMac xs = intercalate ":" $ map hex $ B.unpack xs
	where 
		hex :: (Show a,Integral a) => a -> String
		hex a = showHex a ""

toMac :: [Word8] -> B.ByteString
toMac xs 	| length xs == 6 = B.pack xs
		| otherwise = error "Incorrect length"
{-
toIPa :: Word32 -> String
toIPa n = 
-}
fromIPa :: String -> Word32
fromIPa s = if all (\x -> 0<=x && x<=255) (toIPlist s 4) then 
--TODO:parsing

toIPlist :: String -> Int -> [Word8]
toIPlist s 0 = if s == [] then [] else error "Invalid format"
toIPlist s n = case (break (== '.') s) of
				([],_)->if n==0 then [] else error "Invalid format"
				(a,b) ->(read a):toIPlist (tail' $ snd $ break (== '.') s) (n-1)
					where 
						tail' [] = []
						tail' xs = tail xs