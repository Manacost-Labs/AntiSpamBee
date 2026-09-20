package evaluation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// Read accepts JSONL, bounded to 50,000 examples and 2 MiB per example.
func Read(r io.Reader) ([]Example, error) {
	limited := &io.LimitedReader{R: r, N: 64 << 20}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	var examples []Example
	for scanner.Scan() {
		if len(examples) >= 50000 {
			return nil, fmt.Errorf("dataset exceeds 50000 examples")
		}
		var e Example
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("invalid JSON at line %d", len(examples)+1)
		}
		examples = append(examples, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read dataset: %w", err)
	}
	if limited.N == 0 {
		return nil, fmt.Errorf("dataset reaches 64 MiB limit")
	}
	return examples, nil
}
