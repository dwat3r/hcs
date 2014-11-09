--dump packets from network using packet sockets

import Network.Socket.NetPacket
import Network.Socket

import qualified Data.ByteString as B
import Numeric
--ethernet :: B.ByteString
--ethernet = B.pack [
hex :: (Show a,Integral a) => a -> String
hex a = showHex a ""

brdcast = HWAddr $ B.pack [0xff,0xff,0xff,0xff,0xff,0xff]

sockLL :: IFIndex -> SockAddrLL
sockLL ifx = SockAddrLL (LLProtocol 0x608) ifx hwTypeEther packetOtherhost brdcast
main = do
  s <- socket AF_PACKET Datagram ethProtocolAll
  ifx <- getInterfaceIndex s "enp2s0"
  setPacketOption s packetAddMembership $ PacketMReq ifx mrPromisc brdcast
  rec s 100

rec s 0 = return ()
rec s i = do
  (sal,bs) <- recvFromLL s 1500
  print $ bs
  rec s (i-1)

