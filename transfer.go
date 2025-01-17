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
	"github.com/blocto/solana-go-sdk/program/compute_budget"
	"github.com/blocto/solana-go-sdk/program/metaplex/token_metadata"
	"github.com/blocto/solana-go-sdk/rpc"
	"github.com/blocto/solana-go-sdk/types"
	"github.com/near/borsh-go"
)

const (
	AuthProgramID                  = "auth9SigNpDKz4sJJ1DfCTuZrZNSAgh9sFD3rboVmgg"
	MetaplexBubblegumProgramID     = "BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY"
	MetaplexCoreProgramID          = "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d"
	SPLAccountCompressionProgramID = "cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK"
	SPLNoOpProgramID               = "noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV"
)

type Protocol string

const (
	MplBubblegum     Protocol = "mpl-bubblegum"
	MplCore          Protocol = "mpl-core"
	MplTokenMetadata Protocol = "mpl-token-metadata"
)

type Account types.Account

func (a Account) String() string {
	return types.Account(a).PublicKey.ToBase58()
}

func NewAccount() Account {
	return Account(types.NewAccount())
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
	ctx context.Context
}

func NewClient(ctx context.Context, endpoint string) *Client {
	return &Client{
		rpc: client.NewClient(endpoint),
		ctx: ctx,
	}
}

type Asset struct {
	Interface string `json:"interface"`
	ID        string `json:"id"`
	Grouping  []struct {
		GroupKey   string `json:"group_key"`
		GroupValue string `json:"group_value"`
	} `json:"grouping"`
	Ownership struct {
		Owner    string  `json:"owner"`
		Delegate *string `json:"delegate"`
	} `json:"ownership"`
	Compression struct {
		Eligible    bool   `json:"eligible"`
		Compressed  bool   `json:"compressed"`
		DataHash    string `json:"data_hash"`
		CreatorHash string `json:"creator_hash"`
		AssetHash   string `json:"asset_hash"`
		Tree        string `json:"tree"`
		Seq         uint64 `json:"seq"`
		LeafID      uint64 `json:"leaf_id"`
	} `json:"compression"`
}

type AssetProof struct {
	Root      string   `json:"root"`
	Proof     []string `json:"proof"`
	NodeIndex uint64   `json:"node_index"`
	Leaf      string   `json:"leaf"`
	TreeID    string   `json:"tree_id"`
}

func (asset Asset) Protocol() Protocol {
	switch asset.Interface {
	case "MplCoreAsset":
		return MplCore
	default:
		if asset.Compression.Compressed {
			return MplBubblegum
		}

		return MplTokenMetadata
	}
}

func (asset Asset) Collection() (common.PublicKey, bool) {
	for _, group := range asset.Grouping {
		if group.GroupKey == "collection" {
			return common.PublicKeyFromString(group.GroupValue), true
		}
	}

	return common.PublicKey{}, false
}

func (c Client) assetProof(mint common.PublicKey) (AssetProof, error) {
	bytes, err := c.rpc.RpcClient.Call(c.ctx, "getAssetProof", mint.String())
	if err != nil {
		return AssetProof{}, err
	}

	slog.Debug("Got asset proof", "mint", mint, "bytes", string(bytes))

	var output rpc.JsonRpcResponse[AssetProof]
	err = json.Unmarshal(bytes, &output)
	if err != nil {
		return AssetProof{}, err
	}

	if output.Error != nil {
		return AssetProof{}, output.Error
	}

	return output.Result, nil
}

func (c Client) asset(mint common.PublicKey) (Asset, error) {
	bytes, err := c.rpc.RpcClient.Call(c.ctx, "getAsset", mint.String())
	if err != nil {
		return Asset{}, fmt.Errorf("asset: %w", err)
	}

	slog.Debug("Got asset", "mint", mint, "bytes", string(bytes))

	var output rpc.JsonRpcResponse[Asset]
	err = json.Unmarshal(bytes, &output)
	if err != nil {
		return Asset{}, fmt.Errorf("asset: %w", err)
	}

	if output.Error != nil {
		return Asset{}, fmt.Errorf("asset: %w", output.Error)
	}

	return output.Result, nil
}

func (c Client) mplCoreIx(asset Asset, transfer Transfer) (*types.Instruction, error) {
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
	if collection, ok := asset.Collection(); ok {
		collectionOrDefault = types.AccountMeta{PubKey: collection}
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

	sourceATA, destATA, sourceTR, destTR, err := transfer.addresses(isPNFT)
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

func (c Client) mplBubblegumIx(asset Asset, transfer Transfer) (*types.Instruction, error) {
	type TransferInstructionData struct {
		Discriminator [8]byte
		Root          [32]byte
		DataHash      [32]byte
		CreatorHash   [32]byte
		Nonce         uint64
		Index         uint64
	}

	assetProof, err := c.assetProof(transfer.mint)
	if err != nil {
		return nil, fmt.Errorf("mplbubblegum ix: %w", err)
	}

	proofPath := make([]types.AccountMeta, 0)
	for _, p := range assetProof.Proof {
		proofPath = append(proofPath, types.AccountMeta{PubKey: common.PublicKeyFromString(p)})
	}

	programID := common.PublicKeyFromString(MetaplexBubblegumProgramID)

	data, err := borsh.Serialize(TransferInstructionData{
		Discriminator: [8]byte{163, 52, 200, 231, 140, 3, 69, 186},
		Root:          common.PublicKeyFromString(assetProof.Root),
		DataHash:      common.PublicKeyFromString(asset.Compression.DataHash),
		CreatorHash:   common.PublicKeyFromString(asset.Compression.CreatorHash),
		Nonce:         asset.Compression.LeafID,
		Index:         asset.Compression.LeafID,
	})
	if err != nil {
		return nil, fmt.Errorf("mplbubblegum ix: %w", err)
	}

	treeAuthority, _, err := common.FindProgramAddress(
		[][]byte{common.PublicKeyFromString(assetProof.TreeID).Bytes()},
		common.PublicKeyFromString(MetaplexBubblegumProgramID),
	)
	if err != nil {
		return nil, fmt.Errorf("mplbubblegum ix: %w", err)
	}

	leafOwner := common.PublicKeyFromString(asset.Ownership.Owner)

	leafDelegate := leafOwner
	if asset.Ownership.Delegate != nil {
		leafDelegate = common.PublicKeyFromString(*asset.Ownership.Delegate)
	}

	newLeafOwner := transfer.receiver

	merkleTree := common.PublicKeyFromString(asset.Compression.Tree)

	logWrapper := common.PublicKeyFromString(SPLNoOpProgramID)

	compressionProgram := common.PublicKeyFromString(SPLAccountCompressionProgramID)

	systemProgram := common.SystemProgramID

	accounts := []types.AccountMeta{
		{PubKey: treeAuthority, IsSigner: false, IsWritable: false},
		{PubKey: leafOwner, IsSigner: false, IsWritable: false},
		{PubKey: leafDelegate, IsSigner: false, IsWritable: false},
		{PubKey: newLeafOwner, IsSigner: false, IsWritable: false},
		{PubKey: merkleTree, IsSigner: false, IsWritable: true},
		{PubKey: logWrapper, IsSigner: false, IsWritable: false},
		{PubKey: compressionProgram, IsSigner: false, IsWritable: false},
		{PubKey: systemProgram, IsSigner: false, IsWritable: false},
	}

	for _, p := range proofPath {
		accounts = append(accounts, p)
	}

	return &types.Instruction{ProgramID: programID, Accounts: accounts, Data: data}, nil
}

func (c Client) transferIx(transfer Transfer) (*types.Instruction, error) {
	asset, err := c.asset(transfer.mint)
	if err != nil {
		return nil, fmt.Errorf("transfer ix: %w", err)
	}

	if asset.Ownership.Owner != transfer.sender.String() {
		return nil, fmt.Errorf("transfer ix: sender does not own NFT")
	}

	protocol := asset.Protocol()

	switch protocol {
	case MplBubblegum:
		return c.mplBubblegumIx(asset, transfer)
	case MplCore:
		return c.mplCoreIx(asset, transfer)
	case MplTokenMetadata:
		return c.mplTokenMetadataIx(transfer)
	default:
		return nil, fmt.Errorf("unknown protocol: %s", protocol)
	}
}

func (c Client) transaction(transfer Transfer) (types.Transaction, error) {
	ix, err := c.transferIx(transfer)
	if err != nil {
		return types.Transaction{}, fmt.Errorf("cannot build instruction: %w", err)
	}

	recentBlockhashResponse, err := c.rpc.GetLatestBlockhash(c.ctx)
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

	sig, err := c.rpc.SendTransaction(c.ctx, tx)
	if err != nil {
		return "", fmt.Errorf("cannot send tx: %w", err)
	}

	slog.Debug("Do", "sig", sig)

	return sig, nil
}

func (c Client) getTokenMetadata(address common.PublicKey) (token_metadata.Metadata, error) {
	accountInfo, err := c.rpc.GetAccountInfo(c.ctx, address.String())
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
	mint        common.PublicKey
	sender      common.PublicKey
	priorityFee uint64
	receiver    common.PublicKey
}

func NewTransfer[A ~string, B ~string](mint A, sender B, receiver B, options ...func(*Transfer) error) (Transfer, error) {
	transfer := Transfer{
		mint:     common.PublicKeyFromString(string(mint)),
		sender:   common.PublicKeyFromString(string(sender)),
		receiver: common.PublicKeyFromString(string(receiver)),
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

func (t Transfer) addresses(pnft bool) (sourceATA, destATA, sourceTR, destTR common.PublicKey, err error) {
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
