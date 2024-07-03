package transport

import (
	"github.com/btcsuite/btcd/wire"
)

/*
from
https://github.com/btcsuite/btcd/blob/d881c686e61db35e332fb0309178152dac589b03/wire/message.go#L102
*/
func makeEmptyWireMessage(command string) (wire.Message, error) {
	var msg wire.Message
	switch command {
	case wire.CmdVersion:
		msg = &wire.MsgVersion{}

	case wire.CmdVerAck:
		msg = &wire.MsgVerAck{}

	case wire.CmdSendAddrV2:
		msg = &wire.MsgSendAddrV2{}

	case wire.CmdGetAddr:
		msg = &wire.MsgGetAddr{}

	case wire.CmdAddr:
		msg = &wire.MsgAddr{}

	case wire.CmdAddrV2:
		msg = &wire.MsgAddrV2{}

	case wire.CmdGetBlocks:
		msg = &wire.MsgGetBlocks{}

	case wire.CmdBlock:
		msg = &wire.MsgBlock{}

	case wire.CmdInv:
		msg = &wire.MsgInv{}

	case wire.CmdGetData:
		msg = &wire.MsgGetData{}

	case wire.CmdNotFound:
		msg = &wire.MsgNotFound{}

	case wire.CmdTx:
		msg = &wire.MsgTx{}

	case wire.CmdPing:
		msg = &wire.MsgPing{}

	case wire.CmdPong:
		msg = &wire.MsgPong{}

	case wire.CmdGetHeaders:
		msg = &wire.MsgGetHeaders{}

	case wire.CmdHeaders:
		msg = &wire.MsgHeaders{}

	case wire.CmdAlert:
		msg = &wire.MsgAlert{}

	case wire.CmdMemPool:
		msg = &wire.MsgMemPool{}

	case wire.CmdFilterAdd:
		msg = &wire.MsgFilterAdd{}

	case wire.CmdFilterClear:
		msg = &wire.MsgFilterClear{}

	case wire.CmdFilterLoad:
		msg = &wire.MsgFilterLoad{}

	case wire.CmdMerkleBlock:
		msg = &wire.MsgMerkleBlock{}

	case wire.CmdReject:
		msg = &wire.MsgReject{}

	case wire.CmdSendHeaders:
		msg = &wire.MsgSendHeaders{}

	case wire.CmdFeeFilter:
		msg = &wire.MsgFeeFilter{}

	case wire.CmdGetCFilters:
		msg = &wire.MsgGetCFilters{}

	case wire.CmdGetCFHeaders:
		msg = &wire.MsgGetCFHeaders{}

	case wire.CmdGetCFCheckpt:
		msg = &wire.MsgGetCFCheckpt{}

	case wire.CmdCFilter:
		msg = &wire.MsgCFilter{}

	case wire.CmdCFHeaders:
		msg = &wire.MsgCFHeaders{}

	case wire.CmdCFCheckpt:
		msg = &wire.MsgCFCheckpt{}

	default:
		return nil, wire.ErrUnknownMessage
	}
	return msg, nil
}
