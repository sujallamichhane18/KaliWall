// KaliWall CLI — Command-line interface for managing KaliWall firewall.
// Communicates with the running KaliWall daemon via HTTP REST API.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
)

const baseURL = "http://localhost:8080/api/v1"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "status":
		cmdStatus()
	case "rules":
		cmdRules(args)
	case "block":
		cmdBlock(args)
	case "unblock":
		cmdUnblock(args)
	case "blocked":
		cmdBlocked()
	case "website":
		cmdWebsite(args)
	case "websites":
		cmdWebsites()
	case "threat":
		cmdThreat(args)
	case "threats":
		cmdThreats()
	case "logs":
		cmdLogs(args)
	case "connections":
		cmdConnections()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`KaliWall CLI — Enterprise Firewall Management

Usage: kaliwall-cli <command> [options]

Commands:
  status                    Show daemon & system status
  rules list                List all firewall rules
  rules add <json>          Add a rule (JSON body)
  rules delete <id>         Delete a rule
  rules toggle <id>         Toggle a rule on/off
  rules update <id> <json>  Update a rule
  block <ip> [reason]       Block an IP address
  unblock <ip>              Unblock an IP address
  blocked                   List all blocked IPs
  website block <domain> [reason]   Block a website/domain
  website unblock <domain>          Unblock a website
  websites                  List all blocked websites
  threat <ip>               Check IP threat level (VirusTotal)
  threats                   List all cached VT verdicts
  connections               Show active connections
  logs [--limit N]          Show recent traffic logs
  help                      Show this help

Examples:
  kaliwall-cli status
  kaliwall-cli block 1.2.3.4 "port scanner"
  kaliwall-cli website block facebook.com "policy"
  kaliwall-cli rules add '{"chain":"INPUT","protocol":"tcp","src_ip":"any","dst_ip":"any","src_port":"any","dst_port":"22","action":"DROP","comment":"Block SSH","enabled":true}'
  kaliwall-cli threat 8.8.8.8
  kaliwall-cli logs --limit 50`)
}

// ---------- Commands ----------

func cmdStatus() {
	data, err := apiGet("/stats")
	if err != nil {
		fatal(err)
	}
	d := data.(map[string]interface{})
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KaliWall Daemon Status")
	fmt.Fprintln(tw, "======================")
	fmt.Fprintf(tw, "Hostname:\t%v\n", d["hostname"])
	fmt.Fprintf(tw, "Kernel:\t%v\n", d["kernel"])
	fmt.Fprintf(tw, "Uptime:\t%v\n", d["uptime"])
	fmt.Fprintf(tw, "CPU Usage:\t%.1f%%\n", toFloat(d["cpu_usage_percent"]))
	fmt.Fprintf(tw, "Memory:\t%.1f%%\n", toFloat(d["mem_usage_percent"]))
	fmt.Fprintf(tw, "Load:\t%v\n", d["load_average"])
	fmt.Fprintf(tw, "Total Rules:\t%v\n", d["total_rules"])
	fmt.Fprintf(tw, "Active Rules:\t%v\n", d["active_rules"])
	fmt.Fprintf(tw, "Blocked Today:\t%v\n", d["blocked_today"])
	fmt.Fprintf(tw, "Allowed Today:\t%v\n", d["allowed_today"])
	fmt.Fprintf(tw, "Connections:\t%v\n", d["active_connections"])
	tw.Flush()
}

func cmdRules(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: kaliwall-cli rules <list|add|delete|toggle|update> ...")
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		data, err := apiGet("/rules")
		if err != nil {
			fatal(err)
		}
		rules := data.([]interface{})
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "ID\tENABLED\tCHAIN\tPROTO\tSRC\tDST\tDPORT\tACTION\tCOMMENT\n")
		fmt.Fprintf(tw, "--\t-------\t-----\t-----\t---\t---\t-----\t------\t-------\n")
		for _, r := range rules {
			rule := r.(map[string]interface{})
			enabled := "OFF"
			if b, ok := rule["enabled"].(bool); ok && b {
				enabled = "ON"
			}
			id := fmt.Sprintf("%.8s", str(rule["id"]))
			fmt.Fprintf(tw, "%s\t%s\t%v\t%v\t%v\t%v\t%v\t%v\t%v\n",
				id, enabled, rule["chain"], rule["protocol"],
				rule["src_ip"], rule["dst_ip"], rule["dst_port"],
				rule["action"], rule["comment"])
		}
		tw.Flush()
		fmt.Printf("\nTotal: %d rules\n", len(rules))

	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: kaliwall-cli rules add '<json>'")
			os.Exit(1)
		}
		msg, err := apiPost("/rules", args[1])
		if err != nil {
			fatal(err)
		}
		fmt.Println(msg)

	case "delete":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: kaliwall-cli rules delete <id>")
			os.Exit(1)
		}
		msg, err := apiDelete("/rules/" + args[1])
		if err != nil {
			fatal(err)
		}
		fmt.Println(msg)

	case "toggle":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: kaliwall-cli rules toggle <id>")
			os.Exit(1)
		}
		msg, err := apiPatch("/rules/" + args[1])
		if err != nil {
			fatal(err)
		}
		fmt.Println(msg)

	case "update":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: kaliwall-cli rules update <id> '<json>'")
			os.Exit(1)
		}
		msg, err := apiPut("/rules/"+args[1], args[2])
		if err != nil {
			fatal(err)
		}
		fmt.Println(msg)

	default:
		fmt.Fprintf(os.Stderr, "Unknown rules subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func cmdBlock(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: kaliwall-cli block <ip> [reason]")
		os.Exit(1)
	}
	ip := args[0]
	reason := "Blocked via CLI"
	if len(args) > 1 {
		reason = strings.Join(args[1:], " ")
	}
	body := fmt.Sprintf(`{"ip":"%s","reason":"%s"}`, ip, reason)
	msg, err := apiPost("/blocked", body)
	if err != nil {
		fatal(err)
	}
	fmt.Println(msg)
}

func cmdUnblock(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: kaliwall-cli unblock <ip>")
		os.Exit(1)
	}
	msg, err := apiDelete("/blocked/" + args[0])
	if err != nil {
		fatal(err)
	}
	fmt.Println(msg)
}

func cmdBlocked() {
	data, err := apiGet("/blocked")
	if err != nil {
		fatal(err)
	}
	items := data.([]interface{})
	if len(items) == 0 {
		fmt.Println("No blocked IPs")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "IP\tREASON\tBLOCKED AT\n")
	fmt.Fprintf(tw, "--\t------\t----------\n")
	for _, item := range items {
		b := item.(map[string]interface{})
		fmt.Fprintf(tw, "%v\t%v\t%v\n", b["ip"], b["reason"], b["created_at"])
	}
	tw.Flush()
	fmt.Printf("\nTotal: %d blocked IPs\n", len(items))
}

func cmdWebsite(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: kaliwall-cli website <block|unblock> <domain> [reason]")
		os.Exit(1)
	}

	switch args[0] {
	case "block":
		domain := args[1]
		reason := "Blocked via CLI"
		if len(args) > 2 {
			reason = strings.Join(args[2:], " ")
		}
		body := fmt.Sprintf(`{"domain":"%s","reason":"%s"}`, domain, reason)
		msg, err := apiPost("/websites", body)
		if err != nil {
			fatal(err)
		}
		fmt.Println(msg)
	case "unblock":
		msg, err := apiDelete("/websites/" + args[1])
		if err != nil {
			fatal(err)
		}
		fmt.Println(msg)
	default:
		fmt.Fprintf(os.Stderr, "Unknown website subcommand: %s\n", args[0])
	}
}

func cmdWebsites() {
	data, err := apiGet("/websites")
	if err != nil {
		fatal(err)
	}
	items := data.([]interface{})
	if len(items) == 0 {
		fmt.Println("No blocked websites")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "DOMAIN\tREASON\tBLOCKED AT\n")
	fmt.Fprintf(tw, "------\t------\t----------\n")
	for _, item := range items {
		w := item.(map[string]interface{})
		fmt.Fprintf(tw, "%v\t%v\t%v\n", w["domain"], w["reason"], w["created_at"])
	}
	tw.Flush()
	fmt.Printf("\nTotal: %d blocked websites\n", len(items))
}

func cmdThreat(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: kaliwall-cli threat <ip>")
		os.Exit(1)
	}
	data, err := apiGet("/threat/check/" + args[0])
	if err != nil {
		fatal(err)
	}
	v := data.(map[string]interface{})
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "IP:\t%v\n", v["ip"])
	fmt.Fprintf(tw, "Threat Level:\t%v\n", v["threat_level"])
	fmt.Fprintf(tw, "Malicious:\t%v\n", v["malicious"])
	fmt.Fprintf(tw, "Suspicious:\t%v\n", v["suspicious"])
	fmt.Fprintf(tw, "Harmless:\t%v\n", v["harmless"])
	fmt.Fprintf(tw, "Reputation:\t%v\n", v["reputation"])
	fmt.Fprintf(tw, "Country:\t%v\n", v["country"])
	fmt.Fprintf(tw, "Owner:\t%v\n", v["owner"])
	tw.Flush()
}

func cmdThreats() {
	data, err := apiGet("/threat/cache")
	if err != nil {
		fatal(err)
	}
	items := data.([]interface{})
	if len(items) == 0 {
		fmt.Println("No cached threat intelligence data")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "IP\tLEVEL\tMAL\tSUSP\tHARM\tCOUNTRY\tOWNER\tCONNECTED\tBLOCKED\n")
	fmt.Fprintf(tw, "--\t-----\t---\t----\t----\t-------\t-----\t---------\t-------\n")
	for _, item := range items {
		e := item.(map[string]interface{})
		conn := "No"
		if b, ok := e["has_connection"].(bool); ok && b {
			conn = "Yes"
		}
		blocked := "No"
		if b, ok := e["is_blocked"].(bool); ok && b {
			blocked = "Yes"
		}
		fmt.Fprintf(tw, "%v\t%v\t%v\t%v\t%v\t%v\t%v\t%s\t%s\n",
			e["ip"], e["threat_level"], e["malicious"], e["suspicious"],
			e["harmless"], e["country"], e["owner"], conn, blocked)
	}
	tw.Flush()
	fmt.Printf("\nTotal: %d cached entries\n", len(items))
}

func cmdConnections() {
	data, err := apiGet("/connections")
	if err != nil {
		fatal(err)
	}
	conns := data.([]interface{})
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "PROTO\tLOCAL IP\tLOCAL PORT\tREMOTE IP\tREMOTE PORT\tSTATE\n")
	fmt.Fprintf(tw, "-----\t--------\t----------\t---------\t-----------\t-----\n")
	for _, c := range conns {
		conn := c.(map[string]interface{})
		fmt.Fprintf(tw, "%v\t%v\t%v\t%v\t%v\t%v\n",
			conn["protocol"], conn["local_ip"], conn["local_port"],
			conn["remote_ip"], conn["remote_port"], conn["state"])
	}
	tw.Flush()
	fmt.Printf("\nTotal: %d connections\n", len(conns))
}

func cmdLogs(args []string) {
	limit := "50"
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--limit" || args[i] == "-l" {
			limit = args[i+1]
		}
	}
	data, err := apiGet("/logs?limit=" + limit)
	if err != nil {
		fatal(err)
	}
	entries := data.([]interface{})
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "TIME\tACTION\tSRC IP\tDST IP\tPROTO\tDETAIL\n")
	fmt.Fprintf(tw, "----\t------\t------\t------\t-----\t------\n")
	for _, e := range entries {
		entry := e.(map[string]interface{})
		fmt.Fprintf(tw, "%v\t%v\t%v\t%v\t%v\t%v\n",
			entry["timestamp"], entry["action"],
			entry["src_ip"], entry["dst_ip"],
			entry["protocol"], entry["detail"])
	}
	tw.Flush()
	fmt.Printf("\nShowing %d log entries\n", len(entries))
}

// ---------- HTTP helpers ----------

func apiGet(path string) (interface{}, error) {
	resp, err := http.Get(baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to KaliWall daemon at %s: %v", baseURL, err)
	}
	defer resp.Body.Close()
	return parseResponse(resp)
}

func apiPost(path, jsonBody string) (string, error) {
	resp, err := http.Post(baseURL+path, "application/json", bytes.NewBufferString(jsonBody))
	if err != nil {
		return "", fmt.Errorf("cannot connect to daemon: %v", err)
	}
	defer resp.Body.Close()
	return parseMessage(resp)
}

func apiDelete(path string) (string, error) {
	req, _ := http.NewRequest("DELETE", baseURL+path, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot connect to daemon: %v", err)
	}
	defer resp.Body.Close()
	return parseMessage(resp)
}

func apiPatch(path string) (string, error) {
	req, _ := http.NewRequest("PATCH", baseURL+path, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot connect to daemon: %v", err)
	}
	defer resp.Body.Close()
	return parseMessage(resp)
}

func apiPut(path, jsonBody string) (string, error) {
	req, _ := http.NewRequest("PUT", baseURL+path, bytes.NewBufferString(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot connect to daemon: %v", err)
	}
	defer resp.Body.Close()
	return parseMessage(resp)
}

func parseResponse(resp *http.Response) (interface{}, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid response: %s", string(body))
	}
	if success, ok := result["success"].(bool); !ok || !success {
		msg := "request failed"
		if m, ok := result["message"].(string); ok {
			msg = m
		}
		return nil, fmt.Errorf(msg)
	}
	return result["data"], nil
}

func parseMessage(resp *http.Response) (string, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("invalid response")
	}
	if success, ok := result["success"].(bool); !ok || !success {
		msg := "request failed"
		if m, ok := result["message"].(string); ok {
			msg = m
		}
		return "", fmt.Errorf(msg)
	}
	if m, ok := result["message"].(string); ok {
		return m, nil
	}
	return "OK", nil
}

func str(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func toFloat(v interface{}) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}
