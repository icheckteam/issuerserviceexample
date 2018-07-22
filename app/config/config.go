package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/icheckteam/icertifier.com/blockchain"
	"github.com/pelletier/go-toml"
)

var DefaultConfig Config
var ProofRequest *blockchain.ProofRequest
var DefaultSchemas Schemas

type Config struct {
	TemplateRoot             string `toml:"template_root"`
	Name                     string `toml:"name"`
	Abbreviation             string `toml:"abbreviation"`
	JurisdictionName         string `toml:"jurisdiction_name"`
	JurisdictionAbbreviation string `toml:"jurisdiction_abbreviation"`
	Title                    string `toml:"title"`
	Description              string `toml:"description"`
	Explanation              string `toml:"explanation"`

	Forms         Froms          `toml:"forms"`
	MoreStyles    []string       `toml:"more_styles"`
	MoreScripts   []string       `toml:"more_scripts"`
	SchemaMappers []SchemaMapper `toml:"schema_mappers"`
}

type SchemaMapper struct {
	For        string      `toml:"for"`
	Attributes []Attribute `toml:"attributes"`
}

type Froms []Form

type Form struct {
	Name  string `toml:"name"`
	Title string `toml:"title"`
	Class string `toml:"class"`

	Hidden []Input `toml:"hidden"`
	Inputs []Input `toml:"inputs"`
}

type Input struct {
	Type     string   `toml:"type"`
	Name     string   `toml:"name"`
	Value    string   `toml:"value"`
	Pretty   string   `toml:"pretty"`
	Prefix   string   `toml:"prefix"`
	Required bool     `toml:"required"`
	Disabled bool     `toml:"disabled"`
	Options  []string `toml:"options"`
	Size     int64    `toml:"size"`
	Text     string   `toml:"text"`
	Multiple bool     `toml:"multiple"`
}

type Attribute struct {
	Name   string `toml:"name"`
	From   string `toml:"from"`
	Source string `toml:"source"`
}

type Schema struct {
	Name       string   `json:"name"`
	From       string   `json:"from"`
	Attributes []string `json:"attr_names"`
}

type Schemas []Schema

func loadConfig() Config {
	var config Config
	dat, err := ioutil.ReadFile(fmt.Sprintf("%s/config.toml", os.Getenv("TEMPLATE_PATH")))
	if err != nil {
		panic(err)
	}
	err = toml.Unmarshal(dat, &config)
	if err != nil {
		panic(err)
	}
	return config
}

func loadProofRequest() *blockchain.ProofRequest {
	var config blockchain.ProofRequest
	dat, _ := ioutil.ReadFile(fmt.Sprintf("%s/proof_request.json", os.Getenv("TEMPLATE_PATH")))
	json.Unmarshal(dat, &config)
	return &config
}

func loadSchemas() Schemas {
	var config Schemas
	dat, _ := ioutil.ReadFile(fmt.Sprintf("%s/schemas.json", os.Getenv("TEMPLATE_PATH")))
	json.Unmarshal(dat, &config)
	return config
}

func init() {
	DefaultConfig = loadConfig()
	ProofRequest = loadProofRequest()
	DefaultSchemas = loadSchemas()
}
