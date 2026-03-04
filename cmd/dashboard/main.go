package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"Layer4-Anti/pkg/config"
)

const OWNER = "t.me/deew1771"

func main() {
	mgr := config.NewManager()

	// stats data vars
	var lastTotalReq uint64 = 0
	var lastWhitelistModTime time.Time

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Buffer phím bấm
	inputChan := make(chan string)
	go func() {
		for {
			var input string
			fmt.Scanln(&input)
			inputChan <- input
		}
	}()

	go func() {
		for {
			select {
			case input := <-inputChan:
				switch input {
				case "0":
					mgr.LockStage(config.StageAuto)
				case "1":
					mgr.LockStage(config.StageRateLimit)
				case "2":
					mgr.LockStage(config.StageDPI)
				case "3":
					mgr.LockStage(config.StageChallenge)
				}
			case <-ticker.C:
				info, err := os.Stat("whitelist.txt")
				if err == nil && info.ModTime().After(lastWhitelistModTime) {
					lastWhitelistModTime = info.ModTime()
				}
				currentTotal := lastTotalReq + uint64(getSimulatedTraffic(mgr.CurrentStage))
				pps := currentTotal - lastTotalReq
				lastTotalReq = currentTotal
				activeStage := mgr.CalculateAutoStage(pps)

				renderDashboard(mgr, pps, activeStage)
				fmt.Print("\r\n QUICK COMMAND (0-3) > ")
			}
		}
	}()

	<-sig
	fmt.Println("\n[!] Stopping...")
}

func renderDashboard(mgr *config.Manager, pps uint64, activeStage config.ProtectionStage) {
	// \033[H (Home) dua con tro ve dau, khong xoa man hinh nen khong bi nhay
	fmt.Print("\033[H")

	fmt.Println("====================================================")
	fmt.Println("=          ANTI-DDOS LAYER 4 - SMART CORE          =")
	fmt.Printf("=          Owner: %-32s =\n", OWNER)
	fmt.Println("====================================================")

	status := "AUTO-PILOT"
	if mgr.IsLocked {
		status = "LOCKED"
	}

	fmt.Printf(" STATUS: %-15s | PPS: %-15d\n", status, pps)
	fmt.Printf(" STAGE:  [STAGE %d]         | MODE: ", activeStage)

	switch activeStage {
	case 0:
		fmt.Println("MONITORING    ")
	case 1:
		fmt.Println("RATE LIMIT    ")
	case 2:
		fmt.Println("DPI FILTER    ")
	case 3:
		fmt.Println("CHALLENGE     ")
	}

	fmt.Println("----------------------------------------------------")
	fmt.Println(" STATISTICS:")
	fmt.Printf(" - Total Requests: %-10d | - Peak PPS: %d\n", 0, 0)
	fmt.Printf(" - Passed:         %-10d | - Blocked:  %d\n", 0, 0)
	fmt.Printf(" - Host Online:    %-10d\n", 0)
	fmt.Println("----------------------------------------------------")
	fmt.Println(" CONTROL: Press 0-3 then Enter to change Stage    ")
}

func getSimulatedTraffic(s config.ProtectionStage) int {
	return 0
}
