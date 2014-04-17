{-# LANGUAGE TypeOperators,GADTs,MultiParamTypeClasses,TypeOperators #-}
module Packet.Packet where

--imports:
import qualified Data.ByteString.Lazy as B

--class and abstract data definitions:

data a :+: b where
	(:+:) :: a -> b -> a :+: b
	deriving (Show) --TODO: Show instance pretty prints the field

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