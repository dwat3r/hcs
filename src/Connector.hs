module Connector where

--imports
import Network.Pcap
import System.IO
import Data.Word
import qualified Data.ByteString.Lazy as B
import Data.Binary.Put
import Data.Binary.Get
import Control.Lens
import Packet.Packet
import qualified Packet.Ethernet as E
import qualified Packet.ARP as A
import qualified Packet.IP as I
import qualified Packet.TCP as T
import qualified Packet.UDP as U






parsePacket::(Header b)=>B.ByteString->b
parsePacket bs = undefined