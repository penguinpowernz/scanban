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

	actions := BuildActions(actionMap)

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
