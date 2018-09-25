// Copyright 2017 The go-aichain Authors
// This file is part of the go-aichain library.
//
// The go-aichain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-aichain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-aichain library. If not, see <http://www.gnu.org/licenses/>.

// Package aiconsensus implements the ai consensus engine.
package aiconsensus

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/AICHAIN-CORE/go-aichain/accounts"
	"github.com/AICHAIN-CORE/go-aichain/common"
	"github.com/AICHAIN-CORE/go-aichain/common/hexutil"
	"github.com/AICHAIN-CORE/go-aichain/consensus"
	"github.com/AICHAIN-CORE/go-aichain/consensus/aiconsensus/ethash"
	defaultethash "github.com/AICHAIN-CORE/go-aichain/consensus/ethash"
	"github.com/AICHAIN-CORE/go-aichain/consensus/misc"
	"github.com/AICHAIN-CORE/go-aichain/core/state"
	"github.com/AICHAIN-CORE/go-aichain/core/types"
	"github.com/AICHAIN-CORE/go-aichain/crypto"
	"github.com/AICHAIN-CORE/go-aichain/crypto/sha3"
	"github.com/AICHAIN-CORE/go-aichain/ethdb"
	"github.com/AICHAIN-CORE/go-aichain/log"
	"github.com/AICHAIN-CORE/go-aichain/params"
	"github.com/AICHAIN-CORE/go-aichain/rlp"
	"github.com/AICHAIN-CORE/go-aichain/rpc"
	lru "github.com/hashicorp/golang-lru"
)

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory

	wiggleTime = 500 * time.Millisecond // Random delay (per signer) to allow concurrent signers

	validatorNoTurnDelay   = 3  //ValidatorNoTurnDelay to allow validator no turn to sign
	pooledMinerNoTurnDelay = 5  //Delay to allow pooled miner not in turn to mine
	notPooledMinerDelay    = 10 //Delay to allow validator no turn to mine

	maxBlockPooledMinerNotMined    = 5
	maxBlockOnePooledMinerNotMined = 3
)

// AiConsensus protocol constants.
var (
	PoABlockReward = big.NewInt(2e+17) // Block reward in wei for successfully mining a PoA block
	PoWBlockReward = big.NewInt(1e+18) // Block reward in wei for successfully mining a Pow block

	voteEpochLength = uint64(30000) // Default number of blocks after which to reset the pending votes

	blockValidNumber = uint64(12)

	epochLength = uint64(blockValidNumber * 10) // Default number of blocks after which to checkpoint
	blockPeriod = uint64(1)                     // Default minimum difference between two consecutive block's timestamps

	extraVanity = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal   = 65 // Fixed number of extra-data suffix bytes reserved for signer seal

	nonceAuthVote = hexutil.MustDecode("0xffffffffffffffff") // Magic nonce number to vote on adding a new signer
	nonceDropVote = hexutil.MustDecode("0x0000000000000000") // Magic nonce number to vote on removing a signer.

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	diffValidatorInTurn      = big.NewInt(16) // PoA, no rewards
	diffValidatorNoTurn      = big.NewInt(12) // PoA, no rewards
	diffPooledMinerInTurn    = big.NewInt(8)  // Block difficulty for in-turn signatures, PoA, not allowed to vote
	diffPooledMinerNoTurnPow = big.NewInt(4)  // Block difficulty for out-of-turn signatures, PoW
	diffNotPooledMinerPow    = big.NewInt(2)  // PoW
	diffPow                  = big.NewInt(1)  // PoW
	diffInvalid              = big.NewInt(-1) // Not allowed to mine

	//the last block of the period must be mined by validator/signer to validate the chain, the difficulty of the block header must set to diffValidator.
	//the previous block of the last block can be mined by all miner with difficulty of defaultPowDifficulty.
	//the miner in the miner pool mines the other block in the block valid period.
	//the miner pool is generated in the pool epoch finished.
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// errInvalidVote is returned if a nonce value is something else that the two
	// allowed constants of 0x00..0 or 0xff..f.
	errInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")

	// errInvalidCheckpointVote is returned if a checkpoint/epoch transition block
	// has a vote nonce set to non-zeroes.
	errInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte suffix signature missing")

	// errExtraSigners is returned if non-checkpoint block contain signer data in
	// their extra-data fields.
	errExtraSigners = errors.New("non-checkpoint block contains extra signer list")

	// errInvalidCheckpointSigners is returned if a checkpoint block contains an
	// invalid list of signers (i.e. non divisible by 20 bytes, or not the correct
	// ones).
	errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block is not either
	// of 1 or 2, or if the value does not match the turn of the signer.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorized is returned if a header is signed by a non-authorized entity.
	errUnauthorized = errors.New("unauthorized")

	// errWaitTransactions is returned if an empty block is attempted to be sealed
	// on an instant chain (0 second period). It's important to refuse these as the
	// block reward is zero, so an empty block just bloats the chain... fast.
	errWaitTransactions = errors.New("waiting for transactions")

	//errInvalidHeaderExtra is returned if the format of the block header extra data is incorrect
	errInvalidHeaderExtra = errors.New("invalid block header extra")

	//errInvalidCoinbase is returned if the coinbase is not equal to the public key recovered from signature
	errInvalidCoinbase = errors.New("Verify coinbase by public key recovered from signature failed")

	//errSnapshotNotFound is returned if the Snapshot is not found
	errSnapshotNotFound = errors.New("Snapshot not found.")
)

// SignerFnWithPassphrase is a signer callback function to request a hash to be signed by a
// backing account.
type SignerFnWithPassphraseCached func(accounts.Account, string, []byte) ([]byte, error)

// sigHash returns the hash which is used as input for the proof-of-authority
// signing. It is the hash of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func sigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewKeccak256()

	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // Yes, this will panic if extra is too short
		header.SigData,
		header.Nonce,
	})
	hasher.Sum(hash[:0])
	return hash
}
func sigHashNounce0(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewKeccak256()

	rlp.Encode(hasher, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-65], // Yes, this will panic if extra is too short
		header.SigData,
		types.BlockNonce{},
	})
	hasher.Sum(hash[:0])
	return hash
}

// ecrecover extracts the AICHAIN account address from a signed header.
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the AICHAIN address
	var pubkey []byte
	var err error
	if header.Difficulty.Cmp(diffValidatorInTurn) == 0 ||
		header.Difficulty.Cmp(diffValidatorNoTurn) == 0 ||
		header.Difficulty.Cmp(diffPooledMinerInTurn) == 0 {
		pubkey, err = crypto.Ecrecover(sigHash(header).Bytes(), signature)
		if err != nil {
			return common.Address{}, err
		}
	} else if header.Difficulty.Cmp(diffNotPooledMinerPow) == 0 ||
		header.Difficulty.Cmp(diffPooledMinerNoTurnPow) == 0 ||
		header.Difficulty.Cmp(diffPow) == 0 {
		//nonce set to 0 when genenates the signature
		pubkey, err = crypto.Ecrecover(sigHashNounce0(header).Bytes(), signature)
		if err != nil {
			return common.Address{}, err
		}
	} else {
		return common.Address{}, errUnauthorized
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

// AiConsensus is the Ai consensus engine proposed to support the
// AICHAIN testnet following the Ropsten attacks.
type AiConsensus struct {
	config *params.AiConsensusConfig // Consensus engine configuration parameters
	db     ethdb.Database            // Database to store and retrieve snapshot checkpoints

	recents    *lru.ARCCache // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache // Signatures of recent blocks to speed up mining

	proposals map[common.Address]bool // Current list of proposals we are pushing

	signer     common.Address               // AICHAIN address of the signing key
	signFn     SignerFnWithPassphraseCached // Signer function to authorize hashes with
	passphrase string                       //passphrase to sign
	lock       sync.RWMutex                 // Protects the signer fields

	ethash    *ethash.Ethash
	oldethash *defaultethash.Ethash
}

// New creates a Clique proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
func New(config *params.AiConsensusConfig, db ethdb.Database) *AiConsensus {
	// Set any missing consensus parameters to their defaults
	conf := *config
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}
	if conf.VoteEpoch == 0 {
		conf.VoteEpoch = voteEpochLength
	}
	if conf.Period == 0 {
		config.Period = blockPeriod
	}
	if config.BlockValidNumber == 0 {
		config.BlockValidNumber = blockValidNumber
	}

	if conf.Epoch%conf.BlockValidNumber != 0 || conf.ForkBlockNumber%conf.Epoch != 0 {
		//if the ForkBlockNumber, Epoch, Period is correctly set
		//terminate the program
		log.Error("ForkBlockNumber, Epoch, Period is correctly set for the aiconsensus engine.")
		os.Exit(1)
		return nil
	}
	log.Info("AiConsensus create engine", "period", config.Period, "blockvalid", config.BlockValidNumber, "epoch", config.Epoch, "voteepoch", config.VoteEpoch)
	log.Info("AiConsensus create engine", "maxvalidtornumber", config.MaxValidatorNumber, "maxpooledminernumber", config.MaxPooledMinerNumber, "powdiff", config.EthashDifficulty)
	log.Info("AiConsensus create engine", "forknumber", config.ForkBlockNumber)
	// Allocate the snapshot caches and create the engine
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)

	ethashEngine := ethash.New(ethash.Config{}, conf.EthashDifficulty)
	ethashEngine.SetThreads(1)

	oldethashengine := defaultethash.New(defaultethash.Config{})
	oldethashengine.SetThreads(1)

	validatorNumber := conf.ExtraData[extraVanity]
	poolMinerPos := extraVanity + 1 + int(validatorNumber)*common.AddressLength
	if poolMinerPos > len(conf.ExtraData)-extraSeal {
		log.Error("Invalid AiConsensusConfig Extra.")
		os.Exit(1)
		return nil
	}
	poolMinerNumber := conf.ExtraData[poolMinerPos]
	if len(conf.ExtraData) !=
		extraVanity+1+int(validatorNumber)*common.AddressLength+1+int(poolMinerNumber)*common.AddressLength+extraSeal {
		log.Error("Invalid AiConsensusConfig Extra.")
		os.Exit(1)
		return nil
	}
	for i := 0; i < int(validatorNumber); i++ {
		log.Debug("AiConsensus Config", "validator", conf.ExtraData[extraVanity+1+i*common.AddressLength:extraVanity+1+i*common.AddressLength+common.AddressLength])
	}

	for i := 0; i < int(poolMinerNumber); i++ {
		log.Debug("AiConsensus Config", "pooled miner", conf.ExtraData[poolMinerPos+1+i*common.AddressLength:poolMinerPos+1+i*common.AddressLength+common.AddressLength])
	}

	return &AiConsensus{
		config:     &conf,
		db:         db,
		recents:    recents,
		signatures: signatures,
		proposals:  make(map[common.Address]bool),
		ethash:     ethashEngine,
		oldethash:  oldethashengine,
	}
}

// Ecrecover extracts the AICHAIN account address from a signed header.
func (c *AiConsensus) Ecrecover(header *types.Header) (common.Address, error) {
	return ecrecover(header, c.signatures)
}

// Author implements consensus.Engine, returning the AICHAIN address recovered
// from the signature in the header's extra-data section.
func (c *AiConsensus) Author(header *types.Header) (common.Address, error) {
	if header.Number.Uint64() <= c.config.ForkBlockNumber {
		return c.oldethash.Author(header)
	}
	return ecrecover(header, c.signatures)
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (c *AiConsensus) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return c.verifyHeader(chain, header, nil, seal)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (c *AiConsensus) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := c.verifyHeader(chain, header, headers[:i], seals[i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (c *AiConsensus) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header, seal bool) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	if number == 0 {
		//not verify genesis block
		return nil
	}

	if header.Number.Uint64() >= c.config.GasLimitSoftForkBlockNumber {
		if params.TargetGasLimit == params.GenesisGasLimit {
			params.TargetGasLimit = params.ForkGenesisGasLimit
		}
	}
	if chain.Config().ChainID.Cmp(params.TestnetChainConfig.ChainID) != 0 {
		if header.GasLimit > params.MaximumGasLimit {
			return fmt.Errorf("invalid gasUsed: gasLimit %d, MaximumGasLimit %d", header.GasLimit, params.MaximumGasLimit)
		}
	}

	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}

	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}

	if header.Number.Uint64() <= c.config.ForkBlockNumber {
		return c.oldethash.VerifyEthashHeader(chain, header, parent, false, seal)
	}

	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	if !c.validDifficulty(header.Difficulty) {
		return errInvalidDifficulty
	}

	signer, err := ecrecover(header, c.signatures)
	if err != nil {
		return err
	}

	if header.Difficulty.Cmp(diffValidatorInTurn) == 0 ||
		header.Difficulty.Cmp(diffValidatorNoTurn) == 0 ||
		header.Difficulty.Cmp(diffPooledMinerInTurn) == 0 {
		//PoA block
		// Resolve the authorization key and check against signers
		if header.Difficulty.Cmp(diffValidatorInTurn) == 0 ||
			header.Difficulty.Cmp(diffValidatorNoTurn) == 0 {
			if _, ok := snap.Validator[signer]; !ok {
				return errUnauthorized
			}
		} else {
			if authorized, ok := snap.PooledMiner[signer]; !ok || !authorized {
				return errUnauthorized
			}
		}
		if snap.calcDifficulty(number, signer).Cmp(header.Difficulty) != 0 {
			return errInvalidDifficulty
		}

		// Don't waste time checking blocks from the future
		if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
			return consensus.ErrFutureBlock
		}
		expectedTime := new(big.Int).Add(parent.Time, new(big.Int).SetUint64(c.config.Period))
		if header.Difficulty.Cmp(diffValidatorNoTurn) == 0 {
			expectedTime = new(big.Int).Add(expectedTime, new(big.Int).SetUint64(uint64(validatorNoTurnDelay)))
		} else if header.Difficulty.Cmp(diffPooledMinerInTurn) == 0 && parent.GasUsed*100/parent.GasLimit > 90 {
			expectedTime = parent.Time
		}
		//If there is no tx in block, we should wait for more time.
		if (header.Number.Uint64() >= c.config.ExtraPeriodForkBlockNumber) &&
			(header.TxHash.Hex() == "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421") {
			expectedTime = new(big.Int).Add(expectedTime, new(big.Int).SetUint64(c.config.ExtraPeriod))
		}
		if header.Time.Cmp(expectedTime) < 0 {
			log.Error("Invalid time", "number", number, "hash", header.TxHash, "parent time", parent.Time,
				"header time", header.Time, "expected time", expectedTime)
			return ErrInvalidTimestamp
		}
		// Checkpoint blocks need to enforce zero beneficiary
		checkpoint := (number % c.config.Epoch) == 0
		if checkpoint && header.Coinbase != (common.Address{}) {
			return errInvalidCheckpointBeneficiary
		}
		// Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
		if !bytes.Equal(header.Nonce[:], nonceAuthVote) && !bytes.Equal(header.Nonce[:], nonceDropVote) {
			return errInvalidVote
		}
		voteCheckpoint := (number % c.config.VoteEpoch) == 0
		if voteCheckpoint && !bytes.Equal(header.Nonce[:], nonceDropVote) {
			return errInvalidCheckpointVote
		}
		// Check that the extra-data contains both the vanity and signature
		if len(header.Extra) < extraVanity {
			return errMissingVanity
		}
		if len(header.Extra) < extraVanity+extraSeal {
			return errMissingSignature
		}
		// Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
		signersBytes := len(header.Extra) - extraVanity - extraSeal
		if !checkpoint && signersBytes != 0 {
			return errExtraSigners
		}
		if checkpoint && (signersBytes-2)%common.AddressLength != 0 {
			return errInvalidCheckpointSigners
		}
		// Ensure that the block doesn't contain any uncles which are meaningless in PoA
		if header.UncleHash != uncleHash {
			return errInvalidUncleHash
		}
		// Ensure that the block's difficulty is meaningful (may not be correct at this point)
		if number > 0 {
			if header.Difficulty == nil || !c.validDifficulty(header.Difficulty) {
				return errInvalidDifficulty
			}
		}
		// If all checks passed, validate any special fields for hard forks
		if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
			return err
		}
		// All basic checks passed, verify cascading fields
		return c.verifyCascadingFields(chain, header, parents)
	}
	//PoW block
	// Don't waste time checking blocks from the future
	if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
		return consensus.ErrFutureBlock
	}

	expectedTime := new(big.Int).Add(parent.Time, new(big.Int).SetUint64(c.config.Period))
	if header.Difficulty.Cmp(diffNotPooledMinerPow) == 0 {
		expectedTime = new(big.Int).Add(expectedTime, new(big.Int).SetUint64(uint64(notPooledMinerDelay)))
	} else if header.Difficulty.Cmp(diffPooledMinerNoTurnPow) == 0 {
		expectedTime = new(big.Int).Add(expectedTime, new(big.Int).SetUint64(uint64(pooledMinerNoTurnDelay)))
	}

	//If there is no tx in block, we should wait for more time.
	if (header.Number.Uint64() >= c.config.ExtraPeriodForkBlockNumber) &&
		(header.Difficulty.Cmp(diffPow) != 0) && (header.TxHash.Hex() == "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421") {
		expectedTime = new(big.Int).Add(expectedTime, new(big.Int).SetUint64(c.config.ExtraPeriod))
	}

	if header.Time.Cmp(expectedTime) < 0 {
		return ErrInvalidTimestamp
	}

	if snap.calcDifficulty(number, signer).Cmp(header.Difficulty) != 0 {
		return errInvalidDifficulty
	}

	return c.ethash.VerifyEthashHeader(chain, header, parent, false, seal)

}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (c *AiConsensus) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to it's parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if header.Difficulty.Cmp(diffPooledMinerInTurn) != 0 && parent.Time.Uint64()+c.config.Period > header.Time.Uint64() {
		return ErrInvalidTimestamp
	} else if header.Difficulty.Cmp(diffPooledMinerInTurn) == 0 && parent.Time.Uint64() > header.Time.Uint64() {
		return ErrInvalidTimestamp
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	// If the block is a checkpoint block, verify the validator and pooled miner list
	if number%c.config.Epoch == 0 {
		if err := c.checkValidatorAndPooledMiner(snap, header); err != nil {
			return err
		}
	}
	// All basic checks passed, verify the seal and return
	return c.verifySeal(chain, header, parents)
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (c *AiConsensus) snapshot(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)

	if number < 0 || number < c.config.ForkBlockNumber {
		//no snap shot
		return nil, errSnapshotNotFound
	}

	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := c.recents.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(c.config, c.signatures, c.db, hash); err == nil {
				log.Trace("Loaded voting snapshot form disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}
		// If we're at block zero, make a snapshot
		if number == 0 || number == c.config.ForkBlockNumber {
			//no genesis needed
			var genesis *types.Header
			if number == 0 {
				genesis = chain.GetHeaderByNumber(number)
				if err := c.VerifyHeader(chain, genesis, false); err != nil {
					return nil, err
				}
			} else {
				if len(parents) > 0 {
					genesis = parents[len(parents)-1]
					if genesis.Number.Uint64() != number ||
						genesis.Hash() != hash {
						return nil, errUnknownBlock
					}
					if err := c.verifyHeader(chain, genesis, parents[:len(parents)-1], false); err != nil {
						return nil, err
					}
				} else {
					genesis = chain.GetHeaderByHash(hash)
					if err := c.VerifyHeader(chain, genesis, false); err != nil {
						return nil, err
					}
				}
			}
			validatorNumber := c.config.ExtraData[extraVanity]
			poolMinerPos := extraVanity + 1 + int(validatorNumber)*common.AddressLength
			if poolMinerPos > len(c.config.ExtraData)-extraSeal {
				return nil, errInvalidHeaderExtra
			}
			poolMinerNumber := c.config.ExtraData[poolMinerPos]
			if len(c.config.ExtraData) !=
				extraVanity+1+int(validatorNumber)*common.AddressLength+1+int(poolMinerNumber)*common.AddressLength+extraSeal {
				return nil, errInvalidHeaderExtra
			}

			validator := make([]common.Address, validatorNumber)
			for i := 0; i < int(validatorNumber); i++ {
				copy(validator[i][:], c.config.ExtraData[extraVanity+1+i*common.AddressLength:])
			}

			pooledMiner := make([]common.Address, poolMinerNumber)

			for i := 0; i < len(pooledMiner); i++ {
				copy(pooledMiner[i][:], c.config.ExtraData[poolMinerPos+1+i*common.AddressLength:])
			}
			snap = newSnapshot(c.config, c.signatures, number, genesis.Hash(), validator, pooledMiner)
			if err := snap.store(c.db); err != nil {
				return nil, err
			}
			log.Trace("Stored genesis voting snapshot to disk")
			break
		}
		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers)
	if err != nil {
		return nil, err
	}
	c.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(c.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *AiConsensus) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (c *AiConsensus) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	if header.Number.Uint64() <= c.config.ForkBlockNumber {
		return c.oldethash.VerifySeal(chain, header)
	}
	return c.verifySeal(chain, header, nil)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (c *AiConsensus) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := c.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	if !c.validDifficulty(header.Difficulty) {
		return errInvalidDifficulty
	}
	signer, err := ecrecover(header, c.signatures)
	if err != nil {
		return err
	}
	if header.Difficulty.Cmp(diffValidatorInTurn) == 0 ||
		header.Difficulty.Cmp(diffValidatorNoTurn) == 0 ||
		header.Difficulty.Cmp(diffPooledMinerInTurn) == 0 {
		//PoA block
		// Resolve the authorization key and check against signers
		if header.Difficulty.Cmp(diffValidatorInTurn) == 0 ||
			header.Difficulty.Cmp(diffValidatorNoTurn) == 0 {
			if _, ok := snap.Validator[signer]; !ok {
				return errUnauthorized
			}
		} else {
			if authorized, ok := snap.PooledMiner[signer]; !ok || !authorized {
				return errUnauthorized
			}
		}
		if snap.calcDifficulty(number, signer).Cmp(header.Difficulty) != 0 {
			return errInvalidDifficulty
		}
	} else {
		//PoW block
		if snap.calcDifficulty(number, signer).Cmp(header.Difficulty) != 0 {
			return errInvalidDifficulty
		}
		if header.Coinbase != signer {
			return errInvalidCoinbase
		}
		return c.ethash.VerifySeal(chain, header)
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (c *AiConsensus) Prepare(chain consensus.ChainReader, header *types.Header) error {
	number := header.Number.Uint64()

	if header.GasLimit > params.MaximumGasLimit {
		header.GasLimit = params.MaximumGasLimit
	}

	if header.Number.Uint64() <= c.config.ForkBlockNumber {
		return c.oldethash.Prepare(chain, header)
	}
	// Assemble the voting snapshot to check which votes make sense
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	diff := snap.calcDifficulty(number, c.signer)
	if diff.Cmp(diffInvalid) == 0 {
		//if the signer is not authorized to mine
		return errInvalidDifficulty
	}
	//no coinbase needed
	if diff.Cmp(diffValidatorInTurn) == 0 ||
		diff.Cmp(diffValidatorNoTurn) == 0 {
		header.Coinbase = common.Address{}
	}
	header.Nonce = types.BlockNonce{}
	//only validator has the rights to vote
	if number%c.config.Epoch != 0 &&
		(diff.Cmp(diffValidatorInTurn) == 0 ||
			diff.Cmp(diffValidatorNoTurn) == 0) {
		c.lock.RLock()
		// Gather all the proposals that make sense voting on
		addresses := make([]common.Address, 0, len(c.proposals))
		for address, authorize := range c.proposals {
			if snap.validVote(address, authorize) {
				addresses = append(addresses, address)
			}
		}
		// If there's pending proposals, cast a vote on them
		if len(addresses) > 0 {
			header.Coinbase = addresses[rand.Intn(len(addresses))]
			if c.proposals[header.Coinbase] {
				copy(header.Nonce[:], nonceAuthVote)
			} else {
				copy(header.Nonce[:], nonceDropVote)
			}
		}
		c.lock.RUnlock()
	}
	// Set the correct difficulty
	header.Difficulty = diff

	if diff.Cmp(diffValidatorInTurn) == 0 ||
		diff.Cmp(diffValidatorNoTurn) == 0 ||
		diff.Cmp(diffPooledMinerInTurn) == 0 {
		//PoA block
		// Ensure the extra data has all it's components
		if len(header.Extra) < extraVanity {
			header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
		}
		header.Extra = header.Extra[:extraVanity]

		if number%c.config.Epoch == 0 {
			validators := snap.validators()
			validatorNumber := byte(len(validators))
			header.Extra = append(header.Extra, validatorNumber)
			for _, validator := range validators {
				header.Extra = append(header.Extra, validator[:]...)
			}
			pooledMiners := snap.pooledMiners()
			pooledMinerNumber := byte(len(pooledMiners))
			header.Extra = append(header.Extra, pooledMinerNumber)
			for _, pooledMiner := range pooledMiners {
				header.Extra = append(header.Extra, pooledMiner[:]...)
			}
		}
		header.Extra = append(header.Extra, make([]byte, extraSeal)...)
		// Ensure the timestamp has the correct delay
		parent := chain.GetHeader(header.ParentHash, number-1)
		if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
			return consensus.ErrUnknownAncestor
		}
		header.Time = new(big.Int).Add(parent.Time, new(big.Int).SetUint64(c.config.Period))
		if header.Difficulty.Cmp(diffPooledMinerInTurn) == 0 && parent.GasUsed*100/parent.GasLimit > 90 {
			header.Time = parent.Time
		}
		if header.Time.Int64() < time.Now().Unix() {
			header.Time = big.NewInt(time.Now().Unix())
		}
		if header.Difficulty.Cmp(diffValidatorNoTurn) == 0 {
			//set a delay
			delay := new(big.Int).SetUint64(uint64(validatorNoTurnDelay))
			// log.Info("Header for validator not in turn prepared origin: ", "header time", header.Time)
			header.Time = new(big.Int).Add(header.Time, delay)
			// log.Info("Header for validator not in turn prepared delay:", "delay", delay, "header time", header.Time)
		}
		//the block with GasLimitForkBlockNumber must be the validator block.
		if header.Number.Uint64() >= c.config.GasLimitSoftForkBlockNumber {
			if params.TargetGasLimit == params.GenesisGasLimit {
				params.TargetGasLimit = params.ForkGenesisGasLimit
			}
		}
		if header.Number.Uint64() == c.config.GasLimitSoftForkBlockNumber {
			header.GasLimit = params.TargetGasLimit
		}
	} else {
		//PoW block
		parent := chain.GetHeader(header.ParentHash, number-1)
		if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
			return consensus.ErrUnknownAncestor
		}
		expectedTime := new(big.Int).Add(parent.Time, new(big.Int).SetUint64(c.config.Period))
		if header.Time.Int64() < time.Now().Unix() {
			header.Time = big.NewInt(time.Now().Unix())
		}
		if header.Time.Int64() < expectedTime.Int64() {
			header.Time = expectedTime
		}
		if header.Difficulty.Cmp(diffPooledMinerNoTurnPow) == 0 {
			delay := new(big.Int).SetUint64(uint64(pooledMinerNoTurnDelay))
			header.Time = new(big.Int).Add(header.Time, delay)
		}
		if header.Difficulty.Cmp(diffNotPooledMinerPow) == 0 {
			delay := new(big.Int).SetUint64(uint64(notPooledMinerDelay))
			header.Time = new(big.Int).Add(header.Time, delay)
		}
		header.Extra = append(header.Extra, make([]byte, extraSeal)...)
		return c.ethash.Prepare(chain, header)
	}
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (c *AiConsensus) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	if header.Number.Uint64() <= c.config.ForkBlockNumber {
		return c.oldethash.Finalize(chain, header, state, txs, nil, receipts)
	}
	//rewards calculation
	blockReward := PoWBlockReward
	if chain.Config().IsCoinDelieverDone(header.Number) {
		blockReward = big.NewInt(1)
	}
	if header.Difficulty.Cmp(diffValidatorInTurn) == 0 ||
		header.Difficulty.Cmp(diffValidatorNoTurn) == 0 {
		blockReward = big.NewInt(0)
	} else if header.Difficulty.Cmp(diffPooledMinerInTurn) == 0 {
		blockReward = PoABlockReward
		if chain.Config().IsCoinDelieverDone(header.Number) {
			blockReward = big.NewInt(1)
		}
	}
	if header.Difficulty.Cmp(diffPooledMinerNoTurnPow) == 0 ||
		header.Difficulty.Cmp(diffPow) == 0 ||
		header.Difficulty.Cmp(diffNotPooledMinerPow) == 0 {
		state.AddBalance(header.Coinbase, blockReward)
		return c.ethash.Finalize(chain, header, state, txs, nil, receipts)
	} else if header.Difficulty.Cmp(diffPooledMinerInTurn) == 0 {
		state.AddBalance(header.Coinbase, blockReward)
	} else if header.Difficulty.Cmp(diffValidatorInTurn) != 0 && header.Difficulty.Cmp(diffValidatorNoTurn) != 0 {
		return nil, errInvalidDifficulty
	}
	//If there is no tx in block, we should wait for more time.
	if (header.Number.Uint64() >= c.config.ExtraPeriodForkBlockNumber) &&
		(header.Difficulty.Cmp(diffPow) != 0) && (len(txs) == 0) {
		header.Time = new(big.Int).Add(header.Time, new(big.Int).SetUint64(c.config.ExtraPeriod))
	}
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts), nil
}

// AuthorizeWithPassphrase injects a private key and it's passphrase into the consensus engine to mint new blocks
func (c *AiConsensus) AuthorizeWithPassphrase(signer common.Address, signFn SignerFnWithPassphraseCached, passphrase string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.signer = signer
	c.signFn = signFn
	c.passphrase = passphrase
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (c *AiConsensus) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	header := block.Header()

	if header.Number.Uint64() <= c.config.ForkBlockNumber {
		return c.oldethash.Seal(chain, block, stop)
	}

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return nil, errUnknownBlock
	}

	// Bail out if we're unauthorized to sign a block
	snap, err := c.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return nil, err
	}

	if !c.validDifficulty(header.Difficulty) {
		return nil, errInvalidDifficulty
	}

	if header.Difficulty.Cmp(diffValidatorInTurn) == 0 ||
		header.Difficulty.Cmp(diffValidatorNoTurn) == 0 ||
		header.Difficulty.Cmp(diffPooledMinerInTurn) == 0 {
		//PoA block
		// Resolve the authorization key and check against signers
		if snap.calcDifficulty(number, c.signer).Cmp(header.Difficulty) != 0 {
			return nil, errInvalidDifficulty
		}
		if header.Difficulty.Cmp(diffValidatorInTurn) == 0 ||
			header.Difficulty.Cmp(diffValidatorNoTurn) == 0 {
			if _, ok := snap.Validator[c.signer]; !ok {
				return nil, errUnauthorized
			}
		} else {
			if authorized, ok := snap.PooledMiner[c.signer]; !ok || !authorized {
				return nil, errUnauthorized
			}
		}

		// Sweet, the protocol permits us to sign the block, wait for our time
		delay := time.Unix(header.Time.Int64(), 0).Sub(time.Now()) // nolint: gosimple
		if header.Difficulty.Cmp(diffValidatorNoTurn) == 0 {
			// It's not our turn explicitly to sign, delay it a bit
			wiggle := time.Duration(len(snap.Validator)/2+1) * wiggleTime
			delay += time.Duration(rand.Int63n(int64(wiggle)))

			log.Info("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
		}
		log.Info("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
		if delay > 0 {
			select {
			case <-stop:
				log.Debug("Stop mining for stop signal.")
				return nil, nil
			case <-time.After(delay):
			}
		}

		// Don't hold the signer fields for the entire sealing procedure
		c.lock.RLock()
		signer, signFn, passphrase := c.signer, c.signFn, c.passphrase
		c.lock.RUnlock()

		// Sign all the things!
		sighash, err := signFn(accounts.Account{Address: signer}, passphrase, sigHash(header).Bytes())
		if err != nil {
			return nil, err
		}
		copy(header.Extra[len(header.Extra)-extraSeal:], sighash)
		return block.WithSeal(header), nil
	}
	// Don't hold the signer fields for the entire sealing procedure
	c.lock.RLock()
	signer, signFn, passphrase := c.signer, c.signFn, c.passphrase
	c.lock.RUnlock()

	//PoW block
	if snap.calcDifficulty(number, signer).Cmp(header.Difficulty) != 0 {
		return nil, errInvalidDifficulty
	}
	//no SigData required
	header.SigData = []byte{}

	// Sign all the things!
	sighash, err := signFn(accounts.Account{Address: signer}, passphrase, sigHashNounce0(header).Bytes())
	if err != nil {
		return nil, err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)
	delay := time.Unix(header.Time.Int64(), 0).Sub(time.Now())
	log.Info("Waiting for delay to mine", "delay", common.PrettyDuration(delay))
	if delay > 0 {
		select {
		case <-stop:
			log.Debug("Stop mining for stop signal.")
			return nil, nil
		case <-time.After(delay):
		}
	}
	return c.ethash.Seal(chain, block.WithSeal(header), stop)
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (c *AiConsensus) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	if parent.Number.Uint64()+1 <= c.config.ForkBlockNumber {
		return c.oldethash.CalcDifficulty(chain, time, parent)
	}
	snap, err := c.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	// return CalcDifficulty(snap, c.signer)
	return snap.calcDifficulty(snap.Number+1, c.signer)
}

func (c *AiConsensus) validDifficulty(diff *big.Int) bool {
	if diff.Cmp(diffValidatorInTurn) == 0 ||
		diff.Cmp(diffValidatorNoTurn) == 0 ||
		diff.Cmp(diffPooledMinerInTurn) == 0 ||
		diff.Cmp(diffPooledMinerNoTurnPow) == 0 ||
		diff.Cmp(diffNotPooledMinerPow) == 0 ||
		diff.Cmp(diffPow) == 0 {
		return true
	}
	return false
}

func (c *AiConsensus) checkValidatorAndPooledMiner(snap *Snapshot, header *types.Header) error {
	validators := snap.validators()
	pooledMiners := snap.pooledMiners()

	validatorNumber := header.Extra[extraVanity]
	poolMinerPos := extraVanity + 1 + int(validatorNumber)*common.AddressLength
	if poolMinerPos > len(header.Extra)-extraSeal {
		return errInvalidCheckpointSigners
	}
	poolMinerNumber := header.Extra[poolMinerPos]
	if len(header.Extra) !=
		extraVanity+1+int(validatorNumber)*common.AddressLength+1+int(poolMinerNumber)*common.AddressLength+extraSeal {
		return errInvalidCheckpointSigners
	}
	for i := 0; i < int(validatorNumber); i++ {
		if !bytes.Equal(validators[i][:], header.Extra[extraVanity+1+i*common.AddressLength:extraVanity+1+i*common.AddressLength+common.AddressLength]) {
			return errInvalidCheckpointSigners
		}
	}

	pooledMiner := make([]common.Address, poolMinerNumber)
	for i := 0; i < len(pooledMiner); i++ {
		if !bytes.Equal(pooledMiners[i][:], header.Extra[poolMinerPos+1+i*common.AddressLength:poolMinerPos+1+i*common.AddressLength+common.AddressLength]) {
			return errInvalidCheckpointSigners
		}
	}

	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (c *AiConsensus) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "aiconsensus",
		Version:   "1.0",
		Service:   &API{chain: chain, aiconsensus: c},
		Public:    false,
	}}
}
