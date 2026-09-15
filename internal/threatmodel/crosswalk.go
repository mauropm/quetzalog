package threatmodel

import (
	"embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed crosswalk.yaml
var crosswalkFS embed.FS

// Crosswalk is the embedded framework cross-mapping catalog.
type Crosswalk struct {
	StrideToTechniques   map[string][]string `yaml:"stride_to_techniques"`
	KillChainToTechniques map[string][]string `yaml:"kill_chain_to_techniques"`
	D3FendByTechnique    map[string][]string `yaml:"d3fend_by_technique"`
	Controls             []Control           `yaml:"controls"`
}

// LoadCrosswalk parses the embedded crosswalk catalog.
func LoadCrosswalk() (*Crosswalk, error) {
	data, err := crosswalkFS.ReadFile("crosswalk.yaml")
	if err != nil {
		return nil, fmt.Errorf("read crosswalk: %w", err)
	}
	var cw Crosswalk
	if err := yaml.Unmarshal(data, &cw); err != nil {
		return nil, fmt.Errorf("parse crosswalk: %w", err)
	}
	if cw.StrideToTechniques == nil {
		cw.StrideToTechniques = map[string][]string{}
	}
	if cw.KillChainToTechniques == nil {
		cw.KillChainToTechniques = map[string][]string{}
	}
	if cw.D3FendByTechnique == nil {
		cw.D3FendByTechnique = map[string][]string{}
	}
	return &cw, nil
}
