package cmd

import (
	"fmt"
	"math/rand"
	"time"
)

func PrintBanner() {
	colors := []string{
		"\033[31m", // Merah
		"\033[32m", // Hijau
		"\033[34m", // Biru
		"\033[97m", // Putih
		"\033[38;5;208m", // Orange (kode ANSI 208)
	}
	reset := "\033[0m"

	lines := []string{
		"     ██╗███╗   ███╗██╗  ██╗██╗  ██╗ █████╗  ██████╗ ██╗   ██╗███████╗██████╗ ",
		"     ██║████╗ ████║██║ ██╔╝██║  ██║██╔══██╗██╔═══██╗██║   ██║██╔════╝██╔══██╗",
		"     ██║██╔████╔██║█████╔╝ ███████║╚█████╔╝██║   ██║██║   ██║█████╗  ██████╔╝",
		"██   ██║██║╚██╔╝██║██╔═██╗ ╚════██║██╔══██╗██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗",
		"╚█████╔╝██║ ╚═╝ ██║██║  ██╗     ██║╚█████╔╝╚██████╔╝ ╚████╔╝ ███████╗██║  ██║",
		" ╚════╝ ╚═╝     ╚═╝╚═╝  ╚═╝     ╚═╝ ╚════╝  ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝",
		"                          🔥 jmk48over by rehanHaxor 🔥",
	}

	rand.Seed(time.Now().UnixNano())

	for _, line := range lines {
		for _, char := range line {
			color := colors[rand.Intn(len(colors))]
			fmt.Print(color + string(char) + reset)
		}
		fmt.Println()
	}
}
