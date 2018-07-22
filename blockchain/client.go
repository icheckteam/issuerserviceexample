package blockchain

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

type Cert struct {
	ID         string            `json:"id"`
	Context    string            `json:"context"`
	Property   string            `json:"property"`
	Certifier  string            `json:"certifier"`
	Data       map[string]string `json:"data"`
	Confidence bool              `json:"confidence"`
	Expires    string            `json:"expires"`
	Revocation Revocation        `json:"revocation"`
}

type CertValue struct {
	ID         string            `json:"id,omitempty"`
	Context    string            `json:"context,omitempty"`
	Property   string            `json:"property"`
	Data       map[string]string `json:"data"`
	Confidence bool              `json:"confidence"`
	Expires    string            `json:"expires,omitempty"`
	Revocation *Revocation       `json:"revocation,omitempty"`
}

type Revocation struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type Proof struct {
	Attributes       []string          `json:"attributes"`
	AttributesMapper map[string]string `json:"attributes_mapper"`
	Verified         bool              `json:"verified"`
}

type Client struct {
	API      string
	Name     string
	Password string
	Seed     string
	Address  string
	baseReq  baseReq
}

func NewClient(api, secret, name, password string) Client {
	cli := Client{
		API:      api,
		Name:     name,
		Password: password,
		Seed:     secret,
		baseReq: baseReq{
			ChainID: "ichain",
			Gas:     "50000",
		},
	}
	if err := cli.init(secret); err != nil {
		panic(err)
	}
	return cli
}

type baseReq struct {
	Name          string `json:"name"`
	Password      string `json:"password"`
	AccountNumber string `json:"account_number"`
	Sequence      string `json:"sequence"`
	Gas           string `json:"gas"`
	ChainID       string `json:"chain_id"`
}

type AccountReponse struct {
	AccountValueReponse AccountValueReponse `json:"value"`
}

type AccountValueReponse struct {
	BaseAccount Account
}

type Account struct {
	AccountNumber string `json:"account_number"`
	Sequence      string `json:"sequence"`
}

type claimBody struct {
	BaseRequest baseReq     `json:"base_req"`
	Values      []CertValue `json:"values"`
}

type Identity struct {
	ID    string
	Owner string
}

type ProofRequest struct {
	Property       string                   `json:"property"`
	RequestedAttrs map[string]RequestedAttr `json:"requested_attrs"`
}

type RequestedAttr struct {
	Name         string      `json:"name"`
	Restrictions []SchemaKey `json:"restrictions"`
}

type SchemaKey struct {
	Certifier string `json:"certifier"`
	Property  string `json:"property"`
}

type StoreSeedBody struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Seed     string `json:"seed"`
}

type UpdateKeyBody struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// GetIdent ...
func (c Client) GetIdent(identID string) (*Identity, error) {
	var ident Identity
	_, body, err := c.Do("GET", fmt.Sprintf("/identities/%s", identID), nil)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &ident)
	if err != nil {
		return nil, err
	}
	return &ident, nil
}

// GetCerts get all certs
func (c Client) GetProof(addr string, proofRequest ProofRequest) (Proof, error) {
	proof := Proof{
		AttributesMapper: map[string]string{},
	}
	_, body, err := c.Do("GET", fmt.Sprintf("/accounts/%s/certs", addr), nil)
	if err != nil {
		return proof, err
	}
	certs := []Cert{}
	err = json.Unmarshal(body, &certs)
	if err != nil {
		return proof, err
	}
	for _, attr := range proofRequest.RequestedAttrs {
		for _, cert := range certs {
			if proof.AttributesMapper[attr.Name] == "" {
				for _, schemaKey := range attr.Restrictions {
					if proof.AttributesMapper[attr.Name] != "" {
						break
					}

					if schemaKey.Certifier != "" && cert.Certifier != schemaKey.Certifier {
						continue
					}

					if schemaKey.Property != "" && cert.Property != schemaKey.Property {
						continue
					}
					proof.AttributesMapper[attr.Name] = cert.Data[attr.Name]
					proof.Attributes = append(proof.Attributes, attr.Name)
					break
				}
			}
		}
	}
	if len(proof.Attributes) > 0 {
		proof.Verified = true
	}
	return proof, nil
}

// GetCerts get all certs
func (c Client) Claim(addr string, certs []CertValue) error {
	time.Sleep(5 * time.Second)
	b, err := json.Marshal(claimBody{
		BaseRequest: c.baseReq,
		Values:      certs,
	})
	if err != nil {
		return err
	}
	_, _, err = c.SendTransaction("POST", fmt.Sprintf("/accounts/%s/certs", addr), b)
	return err
}

// GetCerts get all certs
func (c Client) GetAccount(addr string) (AccountReponse, error) {
	acc := AccountReponse{}
	_, body, err := c.Do("GET", fmt.Sprintf("/accounts/%s", addr), nil)
	if err != nil {
		return acc, nil
	}
	err = json.Unmarshal(body, &acc)
	if err != nil {
		return acc, err
	}
	return acc, nil
}

func (c *Client) init(seed string) error {
	key, err := c.GetKey(c.Name)
	if err != nil {
		err = c.StoreKey(StoreSeedBody{
			Seed:     seed,
			Password: c.Password,
			Name:     c.Name,
		})
		if err != nil {
			return fmt.Errorf("store key error: %s", err.Error())
		}
	}
	acc, err := c.GetAccount(key.Address)
	if err != nil {
		return fmt.Errorf("get account key error: %s", err.Error())
	}
	fmt.Printf("$$$$ + %v", acc)
	c.Address = key.Address
	c.baseReq = baseReq{
		Name:          c.Name,
		Password:      c.Password,
		AccountNumber: acc.AccountValueReponse.BaseAccount.AccountNumber,
		Sequence:      acc.AccountValueReponse.BaseAccount.Sequence,
		ChainID:       "ichain",
		Gas:           "50000",
	}
	return nil
}

type Key struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Address string `json:"address"`
	PubKey  string `json:"pub_key"`
}

func (c Client) GetKey(name string) (Key, error) {
	key := Key{}
	_, body, err := c.Do("GET", fmt.Sprintf("/keys/%s", name), nil)
	if err != nil {
		return key, err
	}
	err = json.Unmarshal(body, &key)
	if err != nil {
		return key, err
	}
	return key, nil
}

func (c Client) StoreKey(body StoreSeedBody) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, _, err = c.Do("POST", fmt.Sprintf("/keys"), b)
	if err != nil {
		return nil
	}

	return nil
}

func (c Client) UpdateKey(name string, body UpdateKeyBody) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, _, err = c.Do("PUT", fmt.Sprintf("/keys/%s", name), b)
	if err != nil {
		return nil
	}

	return nil
}

func (c Client) SendTransaction(method, path string, payload []byte) (*http.Response, []byte, error) {
	acc, err := c.GetAccount(c.Address)
	if err != nil {
		return nil, nil, err
	}
	c.baseReq.Sequence = acc.AccountValueReponse.BaseAccount.Sequence
	return c.Do(method, path, payload)
}

func (c Client) Do(method, path string, payload []byte) (*http.Response, []byte, error) {
	var res *http.Response
	var err error
	url := fmt.Sprintf("%v%v", c.API, path)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, nil, err
	}
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	output, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, nil, err
	}
	if res.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("send transaction error: StatusCode: %d Data: %s", res.StatusCode, string(output))
	}

	return res, output, nil
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
