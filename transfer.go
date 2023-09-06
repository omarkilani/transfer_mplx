package transfer_mplx

import (
	"context"
	"log"

	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/blocto/solana-go-sdk/client"
	"github.com/blocto/solana-go-sdk/common"
	_ "github.com/blocto/solana-go-sdk/pkg/pointer"
	"github.com/blocto/solana-go-sdk/program/metaplex/token_metadata"
	_ "github.com/blocto/solana-go-sdk/rpc"
	"github.com/blocto/solana-go-sdk/types"
	"github.com/near/borsh-go"
)

func AccountFromFile(fn string) (types.Account, error) {
	j, err := ioutil.ReadFile(fn)
	if err != nil {
		return types.Account{}, err
	}

	acc, err := AccountFromJSONArray(j)
	if err != nil {
		return types.Account{}, err
	}

	log.Printf("AccountFromFile: loaded pubkey %v from %v\n", acc.PublicKey, fn)
	return acc, nil
}

func AccountFromJSONArray(j []byte) (types.Account, error) {
	var bs []byte
	err := json.Unmarshal(j, &bs)
	if err != nil {
		return types.Account{}, err
	}

	acc, err := types.AccountFromBytes(bs)
	if err != nil {
		return types.Account{}, err
	}

	return acc, nil
}

func AccountFromEnvJSON(env string) (types.Account, error) {
	jsonStr := os.Getenv(env)
	if jsonStr == "" {
		return types.Account{}, nil
	}

	return AccountFromJSONArray([]byte(jsonStr))
}

func GetAccountInfo(endpoint string, address string) (accountInfo client.AccountInfo, err error) {
	c := client.NewClient(endpoint)

	accountInfo, err = c.GetAccountInfo(
		context.TODO(),
		address,
	)

	return accountInfo, err
}

func GetTokenMetadata(endpoint string, address string) (token_metadata.Metadata, error) {
	accountInfo, err := GetAccountInfo(endpoint, address)
	if err != nil {
		log.Printf("GetTokenMetadata: failed to get metadata, err: %v", err)
		return token_metadata.Metadata{}, err
	}

	metadata, err := token_metadata.MetadataDeserialize(accountInfo.Data)
	if err != nil {
		log.Printf("GetTokenMetadata: failed to deserialize metadata, err: %v", err)
		return token_metadata.Metadata{}, err
	}

	return metadata, nil
}

func FindTokenRecordAddress(mint common.PublicKey, ata common.PublicKey) (common.PublicKey, uint8, error) {
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

const AUTH_PROGRAM_ID = "auth9SigNpDKz4sJJ1DfCTuZrZNSAgh9sFD3rboVmgg"

func buildTransferInstruction(payer, sourceATA, destATA, dest, nft,
	metadata, edition, sourceTR, destTR, ruleSet common.PublicKey, data []byte) types.Instruction {
	return types.Instruction{
		ProgramID: common.MetaplexTokenMetaProgramID,
		Accounts: []types.AccountMeta{
			{PubKey: sourceATA, IsWritable: true},
			{PubKey: payer, IsSigner: true, IsWritable: true},
			{PubKey: destATA, IsWritable: true},
			{PubKey: dest},
			{PubKey: nft},
			{PubKey: metadata, IsWritable: true},
			{PubKey: edition},
			{PubKey: sourceTR, IsWritable: true},
			{PubKey: destTR, IsWritable: true},
			{PubKey: payer, IsSigner: true, IsWritable: true},
			{PubKey: payer, IsSigner: true, IsWritable: true},
			{PubKey: common.SystemProgramID},
			{PubKey: common.SysVarInstructionsPubkey},
			{PubKey: common.TokenProgramID},
			{PubKey: common.SPLAssociatedTokenAccountProgramID},
			{PubKey: common.PublicKeyFromString(AUTH_PROGRAM_ID)},
			{PubKey: ruleSet},
		},
		Data: data,
	}
}

func getTransferAddresses(source, dest, nft common.PublicKey, pnft bool) (sourceATA, destATA, sourceTR, destTR common.PublicKey, err error) {
	sourceATA, _, err = common.FindAssociatedTokenAddress(source, nft)
	if err != nil {
		log.Printf("TransferMplx: failed to find a valid associated token address, err: %v", err)
		return sourceATA, destATA, sourceTR, destTR, err
	}

	destATA, _, err = common.FindAssociatedTokenAddress(dest, nft)
	if err != nil {
		log.Printf("TransferMplx: failed to find a valid associated token address, err: %v", err)
		return sourceATA, destATA, sourceTR, destTR, err
	}

	if pnft {
		sourceTR, _, err = FindTokenRecordAddress(nft, sourceATA)
		if err != nil {
			log.Printf("TransferMplx: failed to find a valid token record address, err: %v", err)
			return sourceATA, destATA, sourceTR, destTR, err
		}

		destTR, _, err = FindTokenRecordAddress(nft, destATA)
		if err != nil {
			log.Printf("TransferMplx: failed to find a valid token record address, err: %v", err)
			return sourceATA, destATA, sourceTR, destTR, err
		}
	} else {
		sourceTR = common.MetaplexTokenMetaProgramID
		destTR = common.MetaplexTokenMetaProgramID
	}

	return sourceATA, destATA, sourceTR, destTR, err
}

func TransferMplx(payer types.Account, endpoint string, mint string, receiver string) (string, error) {
	c := client.NewClient(endpoint)

	nft := common.PublicKeyFromString(mint)
	dest := common.PublicKeyFromString(receiver)

	metadata, err := token_metadata.GetTokenMetaPubkey(nft)
	if err != nil {
		log.Printf("TransferMplx: failed to find a valid token metadata, err: %v", err)
		return "", err
	}

	md, err := GetTokenMetadata(endpoint, metadata.String())
	if err != nil {
		log.Printf("TransferMplx: failed to get account info, err: %v", err)
		return "", err
	}

	isPNFT := md.TokenStandard != nil && *md.TokenStandard == token_metadata.ProgrammableNonFungible

	sourceATA, destATA, sourceTR, destTR, err := getTransferAddresses(payer.PublicKey, dest, nft, isPNFT)
	if err != nil {
		log.Printf("TransferMplx: failed to get transfer addresses, err: %v", err)
		return "", err
	}

	log.Printf("TransferMplx: sourceATA %+v sourceTR %v, destATA %+v destTR %v\n", sourceATA, sourceTR, destATA, destTR)

	recentBlockhashResponse, err := c.GetLatestBlockhash(context.Background())
	if err != nil {
		log.Printf("TransferMplx: failed to get recent blockhash, err: %v", err)
		return "", err
	}

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

	edition, err := token_metadata.GetMasterEdition(nft)
	if err != nil {
		log.Printf("TransferMplx: failed to get master edition, err: %v", err)
		return "", err
	}

	ruleSet := common.MetaplexTokenMetaProgramID
	if md.ProgrammableConfig != nil && md.ProgrammableConfig.V1.RuleSet != nil {
		ruleSet = *md.ProgrammableConfig.V1.RuleSet
	}

	log.Printf("TransferMplx: ruleSet %+v\n", ruleSet)

	transferIx := buildTransferInstruction(payer.PublicKey, sourceATA,
		destATA, dest, nft, metadata, edition, sourceTR, destTR, ruleSet, data)

	tx, err := types.NewTransaction(types.NewTransactionParam{
		Signers: []types.Account{payer},
		Message: types.NewMessage(types.NewMessageParam{
			FeePayer:        payer.PublicKey,
			RecentBlockhash: recentBlockhashResponse.Blockhash,
			Instructions: []types.Instruction{
				transferIx,
			},
		}),
	})

	log.Printf("TransferMplx: tx %+v, err %+v\n", tx, err)

	sig, err := c.SendTransaction(context.Background(), tx)
	if err != nil {
		log.Printf("TransferMplx: failed to send tx, err: %v", err)
		return "", err
	}

	log.Printf("TransferMplx: sig: %v", sig)

	return sig, nil
}
