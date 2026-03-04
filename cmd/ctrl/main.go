package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	cmd := os.Args[1]

	switch cmd {
	case "help":
		printHelp()

	case "whitelist":
		if len(os.Args) < 3 {
			fmt.Println("Usage: whitelist load <file> | add <ip> | remove <ip>")
			return
		}
		sub := os.Args[2]
		switch sub {
		case "load":
			if len(os.Args) < 4 {
				return
			}
			fmt.Printf("Loading Whitelist: %s\n", os.Args[3])
		case "add":
			if len(os.Args) < 4 {
				return
			}
			fmt.Printf("Added IP: %s\n", os.Args[3])
		case "remove":
			if len(os.Args) < 4 {
				return
			}
			fmt.Printf("Removed IP: %s\n", os.Args[3])
		}

	case "stage":
		if len(os.Args) < 2 {
			fmt.Println("Usage: stage <0-3>")
			return
		}
		fmt.Printf("Locked Stage: %s\n", os.Args[2])

	default:
		printHelp()
	}
}

func printHelp() {
	fmt.Println("--- Anti-DDoS Help Menu ---")
	fmt.Println("1. help                  : Show menu")
	fmt.Println("2. whitelist load <file> : Load IPs from txt file")
	fmt.Println("3. whitelist add <ip>    : Add single IP")
	fmt.Println("4. whitelist remove <ip> : Remove single IP")
	fmt.Println("5. stage <0-3>           : Lock protection level")
	fmt.Println("---------------------------")
}
