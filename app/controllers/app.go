package controllers

import (
	"strconv"
	"time"

	"github.com/icheckteam/icertifier.com/app"
	"github.com/icheckteam/icertifier.com/app/config"
	"github.com/icheckteam/icertifier.com/blockchain"
	"github.com/revel/revel"
)

type App struct {
	*revel.Controller
}

type Form struct {
	Form  config.Form
	Proof blockchain.Proof
}

func (c App) Index() revel.Result {
	templateFile := "templates/" + config.DefaultConfig.TemplateRoot
	address := c.Request.FormValue("address")
	c.ViewArgs["title"] = config.DefaultConfig.Title
	c.ViewArgs["name"] = config.DefaultConfig.Name
	c.ViewArgs["moreScripts"] = config.DefaultConfig.MoreScripts
	c.ViewArgs["moreStyles"] = config.DefaultConfig.MoreStyles
	c.ViewArgs["address"] = address
	c.ViewArgs["form"] = config.DefaultConfig.Forms[0]
	proof := blockchain.Proof{
		AttributesMapper: map[string]string{},
	}
	if address != "" && config.ProofRequest != nil {
		proof, _ = app.Blockchain.GetProof(address, *config.ProofRequest)
	} else {
		templateFile = "templates/missing_id.html"
	}
	c.ViewArgs["proof"] = proof
	return c.RenderTemplate(templateFile)
}

func (c App) SubmitClaim() revel.Result {
	addr := c.Params.Form.Get("address")
	cert := blockchain.CertValue{
		Property:   c.Params.Form.Get("schema"),
		Data:       map[string]string{},
		Confidence: true,
	}
	for _, schema := range config.DefaultConfig.SchemaMappers {
		if schema.For == c.Params.Form.Get("schema") {
			for _, attr := range schema.Attributes {
				if attr.From == "request" {
					cert.Data[attr.Name] = c.Params.Form.Get(attr.Source)
				} else if attr.From == "literal" {
					cert.Data[attr.Name] = c.Params.Form.Get(attr.Source)
				} else if attr.From == "helper" {
					if attr.Source == "now" {
						cert.Data[attr.Name] = strconv.Itoa(int(time.Now().Unix()))
					}
				}
			}
		}
	}
	result, err := app.Blockchain.Claim(addr, []blockchain.CertValue{cert})
	if err != nil {
		c.Flash.Error(err.Error())
	} else {
		c.Flash.Success(`Successful: block: <a href="http://125.212.225.51:4396/blocks/%s">%s</a>, tx hash: <a href="http://125.212.225.51:4396/txs/%s">%s</a>`, result.Height, result.Height, result.Hash, result.Hash)
	}
	return c.Redirect("/?address=%s", addr)
}
