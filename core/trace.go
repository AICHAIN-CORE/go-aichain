package core

import (
	"fmt"
	"log"
	"math/big"

	"github.com/AICHAIN-CORE/go-aichain/common"
	"github.com/AICHAIN-CORE/go-aichain/consensus/aiconsensus"
	"github.com/AICHAIN-CORE/go-aichain/core/state"
	"github.com/AICHAIN-CORE/go-aichain/core/types"
	"github.com/AICHAIN-CORE/go-aichain/core/vm"
)

var (
	PoABlockReward           = big.NewInt(2e+17) // Block reward in wei for successfully mining a PoA block
	PoWBlockReward           = big.NewInt(1e+18) // Block reward in wei for successfully mining a Pow block
	OldPoWBlockReward        = big.NewInt(3e+18) // Block reward in wei for successfully mining a Pow block
	diffValidatorInTurn      = big.NewInt(16)    // PoA, no rewards
	diffValidatorNoTurn      = big.NewInt(12)    // PoA, no rewards
	diffPooledMinerInTurn    = big.NewInt(8)     // Block difficulty for in-turn signatures, PoA, not allowed to vote
	diffPooledMinerNoTurnPow = big.NewInt(4)     // Block difficulty for out-of-turn signatures, PoW
	diffNotPooledMinerPow    = big.NewInt(2)     // PoW
	diffPow                  = big.NewInt(1)     // PoW
	diffInvalid              = big.NewInt(-1)    // Not allowed to mine
)

// valueTransfer represents a transfer of ether from one account to another
type valueTransfer struct {
	depth           int
	transactionHash common.Hash
	src             common.Address
	srcBalance      *big.Int
	dest            common.Address
	destBalance     *big.Int
	value           *big.Int
	kind            string
}

// transactionTrace contains information about the trace of a single transaction's execution
type transactionTrace struct {
	receipt *types.Receipt
	logs    []*types.Log
	err     error
}

// traceData contains information about the trace of a block's transactions
type traceData struct {
	transactions []*transactionTrace
	transfers    []*valueTransfer
}

// callStackFrame holds internal state on a frame of the call stack during a transaction execution
type callStackFrame struct {
	op             vm.OpCode
	accountAddress common.Address
	transfers      []*valueTransfer
}

// transactionTracer holds state for the trace of a transaction execution
type transactionTracer struct {
	statedb *state.StateDB
	src     common.Address
	stack   []*callStackFrame
	tx      *types.Transaction
	err     error
}

func newTransfer(statedb *state.StateDB, depth int, txHash common.Hash, src, dest common.Address,
	value *big.Int, kind string) *valueTransfer {
	srcBalance := new(big.Int)
	if src != (common.Address{}) {
		srcBalance.Sub(statedb.GetBalance(src), value)
		statedb.SetBalance(src, srcBalance)
	}
	destBalance := new(big.Int).Add(statedb.GetBalance(dest), value)
	statedb.SetBalance(dest, destBalance)

	return &valueTransfer{
		depth:           depth,
		transactionHash: txHash,
		src:             src,
		srcBalance:      srcBalance,
		dest:            dest,
		destBalance:     destBalance,
		value:           value,
		kind:            kind,
	}
}

func newTransactionTracer(statedb *state.StateDB, tx *types.Transaction, bc *BlockChain, block *types.Block) *transactionTracer {
	signer := types.MakeSigner(bc.chainConfig, block.Number())
	from, _ := types.Sender(signer, tx)
	to := common.Address{}
	kind := "CREATION"
	if tx.To() != nil {
		to = *tx.To()
		kind = "TRANSACTION"
	}

	var transfers []*valueTransfer
	if tx.Value().Cmp(big.NewInt(0)) != 0 {
		transfers = []*valueTransfer{newTransfer(statedb, 0, tx.Hash(), from, to, tx.Value(), kind)}
	}

	return &transactionTracer{
		statedb: statedb,
		src:     from,
		stack: []*callStackFrame{
			&callStackFrame{
				accountAddress: to,
				transfers:      transfers,
			},
		},
		tx: tx,
	}
}

func (self *transactionTracer) fixupCreationAddresses(transfers []*valueTransfer,
	address common.Address) {
	for _, transfer := range transfers {
		if transfer.src == (common.Address{}) {
			transfer.src = address
		} else if transfer.dest == (common.Address{}) {
			transfer.dest = address
		}
	}
}

/**
 * addStructLog implements the vm.StructLogCollector interface.
 *
 * We're interested here in capturing value transfers between accounts. To do so, we need to watch
 * for several opcodes: CREATE, CALL, CALLCODE, DELEGATECALL, and SUICIDE. CREATE and CALL can
 * result in transfers to other accounts. CALLCODE and DELEGATECALL don't transfer value, but do
 * create new failure domains, so we track them too. SUICIDE results in a transfer of any remaining
 * balance back to the calling account.
 *
 * Since a failed call, due to out of gas, invalid opcodes, etc, causes all operations for that call
 * to be reverted, we need to track the set of transfers that are pending in each call, which
 * consists of the value transfer made in the current call, if any, and any transfers from
 * successful operations so far. When a call errors, we discard any pending transsfers it had. If
 * it returns successfully - detected by noticing the VM depth has decreased by one - we add that
 * frame's transfers to our own.
 */
func (self *transactionTracer) AddStructLog(entry vm.StructLog) {
	//log.Printf("Depth: %v, Op: %v", entry.Depth, entry.Op)
	// If an error occurred (eg, out of gas), discard the current stack frame
	if entry.Err != nil {
		self.stack = self.stack[:len(self.stack)-1]
		if len(self.stack) == 0 {
			self.err = entry.Err
		}
		return
	}

	// If we just returned from a call
	if entry.Depth == len(self.stack)-1 {
		returnFrame := self.stack[len(self.stack)-1]
		self.stack = self.stack[:len(self.stack)-1]
		topFrame := self.stack[len(self.stack)-1]

		if topFrame.op == vm.CREATE {
			// Now we know our new address, fill it in everywhere.
			topFrame.accountAddress = common.BigToAddress(entry.Stack[len(entry.Stack)-1])
			self.fixupCreationAddresses(returnFrame.transfers, topFrame.accountAddress)
		}

		// Our call succeded, so add any transfers that happened to the current stack frame
		topFrame.transfers = append(topFrame.transfers, returnFrame.transfers...)
	} else if entry.Depth != len(self.stack) {
		log.Panicf("Unexpected stack transition: was %v, now %v", len(self.stack), entry.Depth)
	}

	switch entry.Op {
	case vm.CREATE:
		// CREATE adds a frame to the stack, but we don't know their address yet - we'll fill it in
		// when the call returns.
		value := entry.Stack[len(entry.Stack)-1]
		src := self.stack[len(self.stack)-1].accountAddress

		var transfers []*valueTransfer
		if value.Cmp(big.NewInt(0)) != 0 {
			transfers = []*valueTransfer{
				newTransfer(self.statedb, len(self.stack), self.tx.Hash(), src, common.Address{},
					value, "CREATION")}
		}

		frame := &callStackFrame{
			op:             entry.Op,
			accountAddress: common.Address{},
			transfers:      transfers,
		}
		self.stack = append(self.stack, frame)
	case vm.CALL:
		// CALL adds a frame to the stack with the target address and value
		value := entry.Stack[len(entry.Stack)-3]
		dest := common.BigToAddress(entry.Stack[len(entry.Stack)-2])

		var transfers []*valueTransfer
		if value.Cmp(big.NewInt(0)) != 0 {
			src := self.stack[len(self.stack)-1].accountAddress
			transfers = append(transfers,
				newTransfer(self.statedb, len(self.stack), self.tx.Hash(), src, dest, value,
					"TRANSFER"))
		}

		frame := &callStackFrame{
			op:             entry.Op,
			accountAddress: dest,
			transfers:      transfers,
		}
		self.stack = append(self.stack, frame)
	case vm.CALLCODE:
		fallthrough
	case vm.DELEGATECALL:
		// CALLCODE and DELEGATECALL don't transfer value or change the from address, but do create
		// a separate failure domain.
		frame := &callStackFrame{
			op:             entry.Op,
			accountAddress: self.stack[len(self.stack)-1].accountAddress,
		}
		self.stack = append(self.stack, frame)
	case vm.SELFDESTRUCT:
		// SUICIDE results in a transfer back to the calling address.
		frame := self.stack[len(self.stack)-1]
		value := self.statedb.GetBalance(frame.accountAddress)

		dest := self.src
		if len(self.stack) > 1 {
			dest = self.stack[len(self.stack)-2].accountAddress
		}

		if value.Cmp(big.NewInt(0)) != 0 {
			frame.transfers = append(frame.transfers, newTransfer(self.statedb, len(self.stack),
				self.tx.Hash(), frame.accountAddress, dest, value, "SELFDESTRUCT"))
		}
	}
}

// Checks invariants, and returns the error the transaction encountered, if any
func (self *transactionTracer) finish(receipt *types.Receipt) error {
	if len(self.stack) > 1 {
		log.Panicf("Transaction not done: %v frames still on the stack", len(self.stack))
	} else if len(self.stack) == 1 {
		// Find any unset addresses due to contract creation and set them
		self.fixupCreationAddresses(self.stack[0].transfers, receipt.ContractAddress)
	}

	return self.err
}

func recordRewards(chain *BlockChain, statedb *state.StateDB, block *types.Block, data *traceData) {
	blockReward := PoWBlockReward
	if block.NumberU64() <= chain.Config().AiConsensus.ForkBlockNumber {
		blockReward = OldPoWBlockReward
	}
	if chain.Config().IsCoinDelieverDone(block.Number()) {
		blockReward = big.NewInt(1)
	}
	if block.Difficulty().Cmp(diffValidatorInTurn) == 0 ||
		block.Difficulty().Cmp(diffValidatorNoTurn) == 0 {
		blockReward = big.NewInt(0)
	} else if block.Difficulty().Cmp(diffPooledMinerInTurn) == 0 {
		blockReward = PoABlockReward
		if chain.Config().IsCoinDelieverDone(block.Number()) {
			blockReward = big.NewInt(1)
		}
	}

	var err error
	coinbase := block.Coinbase()
	if chain.chainConfig.AiConsensus != nil && block.Number().Uint64() > chain.chainConfig.AiConsensus.ForkBlockNumber {
		if aiconsensus, ok := chain.engine.(*aiconsensus.AiConsensus); ok {
			coinbase, err = aiconsensus.Ecrecover(block.Header())
			if err != nil {
				return
			}
		}
	}

	data.transfers = append(data.transfers,
		newTransfer(statedb, 0, common.Hash{}, common.Address{}, coinbase, blockReward, "MINED"))
}

/* Traces a block. Assumes it's already validated. */
func traceBlock(blockchain *BlockChain, block *types.Block) (*traceData, error) {
	data := &traceData{}

	signer := types.MakeSigner(blockchain.chainConfig, block.Number())
	parent := blockchain.GetBlockByHash(block.ParentHash())
	if parent == nil {
		return nil, fmt.Errorf("Could not retrieve parent block for hash %v",
			block.ParentHash().Hex())
	}

	statedb, err := blockchain.StateAt(blockchain.GetBlockByHash(block.ParentHash()).Root())
	if err != nil {
		return nil, err
	}

	statedb2, err := blockchain.StateAt(blockchain.GetBlockByHash(block.ParentHash()).Root())
	if err != nil {
		return nil, err
	}

	gasPool := new(GasPool).AddGas(block.GasLimit())

	for i, tx := range block.Transactions() {
		trace := &transactionTrace{}

		tracer := vm.NewStructLogger(&vm.LogConfig{DisableMemory: false, DisableStack: false, DisableStorage: false})
		message, _ := tx.AsMessage(signer)
		gas := message.Gas()
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		trace.receipt, _, err = ApplyTransaction(blockchain.Config(), blockchain, nil, gasPool, statedb, block.Header(), tx, &gas, vm.Config{Debug: true, Tracer: tracer})
		if err != nil {
			log.Fatalf("Failed to trace transaction %v: %v", tx.Hash().Hex(), err)
			continue
		}

		if trace.receipt.Status == 1 {
			statedb2.Prepare(tx.Hash(), block.Hash(), i)
			transactionTracer := newTransactionTracer(statedb2, tx, blockchain, block)
			for _, structLog := range tracer.StructLogs() {
				transactionTracer.AddStructLog(structLog)
				// if index == len(tracer.StructLogs())-1 {
				// 	bytes, _ := structLog.MarshalJSON()
				// 	fmt.Printf("%s\n", string(bytes))
				// }
			}

			trace.err = transactionTracer.finish(trace.receipt)
			if len(transactionTracer.stack) == 1 {
				data.transfers = append(data.transfers, transactionTracer.stack[0].transfers...)
			}
		}

		// Account for transaction fees
		from, _ := types.Sender(signer, tx)
		data.transfers = append(data.transfers, newTransfer(statedb2, 0, tx.Hash(), from,
			block.Coinbase(), new(big.Int).Mul(new(big.Int).SetInt64(int64(trace.receipt.GasUsed)), tx.GasPrice()), "FEE"))

		data.transactions = append(data.transactions, trace)
	}
	recordRewards(blockchain, statedb2, block, data)

	return data, nil
}
