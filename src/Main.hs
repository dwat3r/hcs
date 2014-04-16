module Main where

import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens

{-
TODO:
1.make data for all packets
2.make default instance for all packets
3.make attachable instance for all legal packet header combinations
4.make a shitload of smart constructors for packet types
5.make smart bounds checker for field values
6.make de-parser and parser for headers
-}
--general field datatype:
data Field a = F {value :: a,
				  width :: Int}
				  deriving (Show)
--smart constructor for field:
field :: (Num a,Ord a) => a -> Int -> Either String (Field a)
field val width | val < 0 || val > (2^width-1) = Left "Value not in bounds"
				| otherwise 				   = Right $ F val width

class Header a where
	toBytes :: a -> B.ByteString
	fromBytes :: B.ByteString -> a