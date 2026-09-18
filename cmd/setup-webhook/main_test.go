package main

import (
	"slices"
	"testing"
)

func TestDefaultCommandsExposeOnboardingAndModerationGuide(t *testing.T) {
	commands := defaultCommands()
	names := make([]string, 0, len(commands))
	for _, command := range commands {
		names = append(names, command.Command)
	}
	for _, required := range []string{"start", "help", "report", "status", "protection", "ban", "unban"} {
		if !slices.Contains(names, required) {
			t.Fatalf("default commands %v do not contain %q", names, required)
		}
	}
}
