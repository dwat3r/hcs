{-# LANGUAGE TypeOperators,GADTs,MultiParamTypeClasses,TypeOperators #-}
module Packet.Packet where

--imports:
import qualified Data.ByteString.Lazy as B

--class and abstract data definitions:
data a :+: b where
	PAppend :: a -> b -> a :+: b
	deriving (Show) --TODO: Show instance pretty prints the field
--de-concatenation
--TODO: implement a Zipper here
pLeft :: a :+: b -> a
pLeft (PAppend a b) = a

pRight :: a :+: b -> b
pRight (PAppend a b) = b

infixr +++

class Attachable a b where
	(+++) :: a -> b -> (a :+: b)
	a +++ b = PAppend a b

class Header a where
	toBytes :: a -> B.ByteString
	fromBytes :: B.ByteString -> a