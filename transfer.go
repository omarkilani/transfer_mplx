package transfer_mplx

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"encoding/base64"
	"github.com/blocto/solana-go-sdk/client"
	"github.com/blocto/solana-go-sdk/common"
	_ "github.com/blocto/solana-go-sdk/pkg/pointer"
	"github.com/blocto/solana-go-sdk/program/compute_budget"
	"github.com/blocto/solana-go-sdk/program/metaplex/token_metadata"
	_ "github.com/blocto/solana-go-sdk/rpc"
	"github.com/blocto/solana-go-sdk/types"
	"github.com/near/borsh-go"
)

const (
	AuthProgramID         = "auth9SigNpDKz4sJJ1DfCTuZrZNSAgh9sFD3rboVmgg"
	MetaplexCoreProgramID = "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d"
)

type Protocol string

const (
	MplCore          Protocol = "mpl-core"
	MplTokenMetadata Protocol = "mpl-token-metadata"
)

type Account types.Account

func (a Account) String() string {
	return types.Account(a).PublicKey.ToBase58()
}

func AccountFromBase58(input string) (Account, error) {
	account, err := types.AccountFromBase58(input)
	if err != nil {
		return Account{}, err
	}

	return Account(account), nil
}

func AccountFromJSON(input []byte) (Account, error) {
	var bytes []byte
	if err := json.Unmarshal(input, &bytes); err != nil {
		return Account{}, err
	}

	account, err := types.AccountFromBytes(bytes)
	if err != nil {
		return Account{}, err
	}

	return Account(account), nil
}

func AccountFromFile(fn string) (Account, error) {
	json, err := os.ReadFile(fn)
	if err != nil {
		return Account{}, err
	}

	return AccountFromJSON(json)
}

func AccountFromEnvJSON(env string) (Account, error) {
	json := os.Getenv(env)
	if json == "" {
		return Account{}, fmt.Errorf("no env var %s", env)
	}

	return AccountFromJSON([]byte(json))
}

type Client struct {
	rpc *client.Client
}

func NewClient(endpoint string) *Client {
	return &Client{
		rpc: client.NewClient(endpoint),
	}
}

func (c Client) mplCoreIx(transfer Transfer) (*types.Instruction, error) {
	data, err := borsh.Serialize(struct {
		Instruction uint8
		Something   *string
	}{Instruction: 14, Something: nil})
	if err != nil {
		return nil, err
	}

	programID := common.PublicKeyFromString(MetaplexCoreProgramID)

	defaultAccount := types.AccountMeta{PubKey: programID}

	collectionOrDefault := defaultAccount
	if transfer.collection != nil {
		collectionOrDefault = types.AccountMeta{PubKey: *transfer.collection}
	}

	return &types.Instruction{
		ProgramID: programID,
		Accounts: []types.AccountMeta{
			{PubKey: transfer.mint, IsWritable: true},
			collectionOrDefault,
			{PubKey: transfer.sender, IsSigner: true, IsWritable: true},
			defaultAccount,
			{PubKey: transfer.receiver},
			defaultAccount,
			defaultAccount,
		},
		Data: data,
	}, nil
}

func (c Client) mplTokenMetadataIx(transfer Transfer) (*types.Instruction, error) {
	metadata, err := token_metadata.GetTokenMetaPubkey(transfer.mint)
	if err != nil {
		return nil, fmt.Errorf("no token metadata address: %w", err)
	}

	md, err := c.getTokenMetadata(metadata)
	if err != nil {
		return nil, fmt.Errorf("no token metadata: %w", err)
	}

	isPNFT := md.TokenStandard != nil && *md.TokenStandard == token_metadata.ProgrammableNonFungible

	sourceATA, destATA, sourceTR, destTR, err := transfer.Addresses(isPNFT)
	if err != nil {
		return nil, fmt.Errorf("no transfer addresses: %w", err)
	}

	slog.Debug("MplxTransferIx", "sourceATA", sourceATA, "sourceTR", sourceTR, "destATA", destATA, "destTR", destTR)

	data, err := borsh.Serialize(struct {
		Instruction token_metadata.Instruction
		Data        TransferArgs
	}{
		Instruction: token_metadata.InstructionTransfer,
		Data: TransferArgs{
			V1: TransferArgsV1{
				Amount:            1,
				AuthorizationData: nil,
			},
		},
	})

	edition, err := token_metadata.GetMasterEdition(transfer.mint)
	if err != nil {
		return nil, fmt.Errorf("no master edition: %w", err)
	}

	ruleSet := common.MetaplexTokenMetaProgramID
	if md.ProgrammableConfig != nil && md.ProgrammableConfig.V1.RuleSet != nil {
		ruleSet = *md.ProgrammableConfig.V1.RuleSet
	}

	slog.Debug("mplTokenMetadataIx", "ruleSet", ruleSet)

	return &types.Instruction{
		ProgramID: common.MetaplexTokenMetaProgramID,
		Accounts: []types.AccountMeta{
			{PubKey: sourceATA, IsWritable: true},
			{PubKey: transfer.sender, IsSigner: true, IsWritable: true},
			{PubKey: destATA, IsWritable: true},
			{PubKey: transfer.receiver},
			{PubKey: transfer.mint},
			{PubKey: metadata, IsWritable: true},
			{PubKey: edition},
			{PubKey: sourceTR, IsWritable: true},
			{PubKey: destTR, IsWritable: true},
			{PubKey: transfer.sender, IsSigner: true, IsWritable: true},
			{PubKey: transfer.sender, IsSigner: true, IsWritable: true},
			{PubKey: common.SystemProgramID},
			{PubKey: common.SysVarInstructionsPubkey},
			{PubKey: common.TokenProgramID},
			{PubKey: common.SPLAssociatedTokenAccountProgramID},
			{PubKey: common.PublicKeyFromString(AuthProgramID)},
			{PubKey: ruleSet},
		},
		Data: data,
	}, nil
}

func (c Client) transferIx(transfer Transfer) (*types.Instruction, error) {
	switch transfer.protocol {
	case MplCore:
		return c.mplCoreIx(transfer)
	case MplTokenMetadata:
		return c.mplTokenMetadataIx(transfer)
	default:
		return nil, fmt.Errorf("unknown protocol: %s", transfer.protocol)
	}
}

func (c Client) transaction(transfer Transfer) (types.Transaction, error) {
	ix, err := c.transferIx(transfer)
	if err != nil {
		return types.Transaction{}, fmt.Errorf("cannot build instruction: %w", err)
	}

	recentBlockhashResponse, err := c.rpc.GetLatestBlockhash(context.Background())
	if err != nil {
		return types.Transaction{}, fmt.Errorf("no recent blockhash: %w", err)
	}

	instructions := []types.Instruction{*ix}

	if transfer.priorityFee > 0 {
		priorityFeeIx := compute_budget.SetComputeUnitPrice(compute_budget.SetComputeUnitPriceParam{
			MicroLamports: transfer.priorityFee,
		})

		instructions = append([]types.Instruction{priorityFeeIx}, instructions...)
	}

	return types.NewTransaction(types.NewTransactionParam{
		Message: types.NewMessage(types.NewMessageParam{
			FeePayer:        transfer.sender,
			RecentBlockhash: recentBlockhashResponse.Blockhash,
			Instructions:    instructions,
		}),
	})
}

func (c Client) RawTx(transfer Transfer) (string, error) {
	tx, err := c.transaction(transfer)
	if err != nil {
		return "", fmt.Errorf("cannot build transaction: %w", err)
	}

	rawTx, err := tx.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize tx, err: %v", err)
	}

	return base64.StdEncoding.EncodeToString(rawTx), nil
}

func (c Client) Do(transfer Transfer, signer Account) (string, error) {
	tx, err := c.transaction(transfer)
	if err != nil {
		return "", fmt.Errorf("cannot build transaction: %w", err)
	}

	data, err := tx.Message.Serialize()
	if err != nil {
		return "", fmt.Errorf("cannot serialize message, err: %v", err)
	}

	if err := tx.AddSignature(types.Account(signer).Sign(data)); err != nil {
		return "", fmt.Errorf("cannot sign tx: %w", err)
	}

	slog.Debug("Do", "tx", tx, "err", err)

	sig, err := c.rpc.SendTransaction(context.Background(), tx)
	if err != nil {
		return "", fmt.Errorf("cannot send tx: %w", err)
	}

	slog.Debug("Do", "sig", sig)

	return sig, nil
}

func (c Client) getTokenMetadata(address common.PublicKey) (token_metadata.Metadata, error) {
	accountInfo, err := c.rpc.GetAccountInfo(context.TODO(), address.String())
	if err != nil {
		return token_metadata.Metadata{}, fmt.Errorf("no account info: %w", err)
	}

	metadata, err := token_metadata.MetadataDeserialize(accountInfo.Data)
	if err != nil {
		return token_metadata.Metadata{}, fmt.Errorf("cannot deserialize metadata: %w", err)
	}

	return metadata, nil
}

type Transfer struct {
	collection  *common.PublicKey
	mint        common.PublicKey
	sender      common.PublicKey
	priorityFee uint64
	protocol    Protocol
	receiver    common.PublicKey
}

func NewTransfer[A ~string, B ~string](mint A, sender B, receiver B, options ...func(*Transfer) error) (Transfer, error) {
	transfer := Transfer{
		mint:     common.PublicKeyFromString(string(mint)),
		sender:   common.PublicKeyFromString(string(sender)),
		receiver: common.PublicKeyFromString(string(receiver)),
		protocol: MplTokenMetadata,
	}

	for _, option := range options {
		if err := option(&transfer); err != nil {
			return Transfer{}, err
		}
	}

	return transfer, nil
}

func WithPriorityFee(priorityFee uint64) func(*Transfer) error {
	return func(t *Transfer) error {
		t.priorityFee = priorityFee
		return nil
	}
}

func WithProtocol(protocol Protocol) func(*Transfer) error {
	return func(t *Transfer) error {
		t.protocol = protocol
		return nil
	}
}

func WithCollection[A ~string](collection A) func(*Transfer) error {
	return func(t *Transfer) error {
		c := common.PublicKeyFromString(string(collection))
		t.collection = &c
		return nil
	}
}

func (t Transfer) Addresses(pnft bool) (sourceATA, destATA, sourceTR, destTR common.PublicKey, err error) {
	sourceATA, _, err = common.FindAssociatedTokenAddress(t.sender, t.mint)
	if err != nil {
		return sourceATA, destATA, sourceTR, destTR, fmt.Errorf("no associated token address for source: %w", err)
	}

	destATA, _, err = common.FindAssociatedTokenAddress(t.receiver, t.mint)
	if err != nil {
		return sourceATA, destATA, sourceTR, destTR, fmt.Errorf("no associated token address for dest: %w", err)
	}

	if pnft {
		sourceTR, _, err = findTokenRecordAddress(t.mint, sourceATA)
		if err != nil {
			return sourceATA, destATA, sourceTR, destTR, fmt.Errorf("no token record address for source: %w", err)
		}

		destTR, _, err = findTokenRecordAddress(t.mint, destATA)
		if err != nil {
			return sourceATA, destATA, sourceTR, destTR, fmt.Errorf("no token record address for dest: %w", err)
		}
	} else {
		sourceTR = common.MetaplexTokenMetaProgramID
		destTR = common.MetaplexTokenMetaProgramID
	}

	return sourceATA, destATA, sourceTR, destTR, err
}

func findTokenRecordAddress(mint common.PublicKey, ata common.PublicKey) (common.PublicKey, uint8, error) {
	seeds := [][]byte{}
	seeds = append(seeds, []byte("metadata"))
	seeds = append(seeds, common.MetaplexTokenMetaProgramID.Bytes())
	seeds = append(seeds, mint.Bytes())
	seeds = append(seeds, []byte("token_record"))
	seeds = append(seeds, ata.Bytes())

	return common.FindProgramAddress(seeds, common.MetaplexTokenMetaProgramID)
}

type MplxPayload struct {
	Map map[string]any
}

type AuthorizationData struct {
	Payload MplxPayload
}

type TransferArgsV1 struct {
	Amount            uint64
	AuthorizationData *AuthorizationData
}

type TransferArgs struct {
	Enum borsh.Enum `borsh_enum:"true"`
	V1   TransferArgsV1
}
