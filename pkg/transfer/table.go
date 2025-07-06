package transfer

import (
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
)

func TransferDeltaAccount(
	perform func(t table.Writer),
) {
	t := table.NewWriter()
	t.SetStyle(table.StyleColoredBlackOnGreenWhite)
	t.SetOutputMirror(os.Stdout)

	perform(t)
	t.Render()
}
