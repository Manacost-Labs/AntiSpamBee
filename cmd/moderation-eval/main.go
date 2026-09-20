// moderation-eval is an offline tool: no API keys, model calls or Telegram actions.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"antispambee/internal/evaluation"
)

func main() {
	input := flag.String("input", "", "labeled JSONL dataset")
	split := flag.String("split", "test", "dev or test")
	mode := flag.String("mode", "rules", "rules or replay (saved v3 model responses)")
	representative := flag.Bool("representative", false, "only independent production samples")
	flag.Parse()
	if err := run(*input, *split, *mode, *representative); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path, split, mode string, representative bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	examples, err := evaluation.Read(f)
	if err != nil {
		return err
	}
	report, err := evaluation.Evaluate(examples, split, mode, representative)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
