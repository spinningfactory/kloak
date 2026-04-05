package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

//go:embed static
var staticFS embed.FS

var clickhouseURL string

type graphRow struct {
	PodName         string  `json:"pod_name"`
	PodNS           string  `json:"pod_ns"`
	SecretName      string  `json:"secret_name"`
	SecretNS        string  `json:"secret_ns"`
	RewriteCount    float64 `json:"rewrite_count"`
}

type node struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Type    string `json:"type"`
	Runtime string `json:"runtime,omitempty"`
}

type edge struct {
	Source string  `json:"source"`
	Target string  `json:"target"`
	Weight float64 `json:"weight"`
}

type graphResponse struct {
	Nodes []node `json:"nodes"`
	Edges []edge `json:"edges"`
}

type secretRow struct {
	Name          string  `json:"name"`
	Namespace     string  `json:"namespace"`
	TotalRewrites float64 `json:"total_rewrites"`
}

type topSecretsResponse struct {
	Secrets []secretRow `json:"secrets"`
}

func detectRuntime(podName string) string {
	lower := strings.ToLower(podName)
	switch {
	case strings.Contains(lower, "go"):
		return "go"
	case strings.Contains(lower, "python"):
		return "python"
	case strings.Contains(lower, "rust"):
		return "rust"
	default:
		return "unknown"
	}
}

func queryClickHouse(chURL, sql string) ([]byte, error) {
	resp, err := http.Get(chURL + "/?query=" + url.QueryEscape(sql))
	if err != nil {
		return nil, fmt.Errorf("clickhouse request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("clickhouse returned %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func handleGraph(w http.ResponseWriter, r *http.Request) {
	sql := `SELECT
    Attributes['pod_name'] as pod_name,
    Attributes['pod_namespace'] as pod_ns,
    Attributes['secret_name'] as secret_name,
    Attributes['secret_namespace'] as secret_ns,
    argMax(Value, TimeUnix) as rewrite_count
FROM otel.otel_metrics_sum
WHERE MetricName = 'kloak_tls_rewrite_total'
  AND Attributes['pod_name'] != ''
GROUP BY pod_name, pod_ns, secret_name, secret_ns
FORMAT JSONEachRow`

	body, err := queryClickHouse(clickhouseURL, sql)
	if err != nil {
		log.Printf("graph query error: %v", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	nodeMap := make(map[string]node)
	var edges []edge

	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if line == "" {
			continue
		}
		var row graphRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			log.Printf("parse row error: %v", err)
			continue
		}

		podID := "pod:" + row.PodNS + "/" + row.PodName
		secretID := "secret:" + row.SecretNS + "/" + row.SecretName

		if _, ok := nodeMap[podID]; !ok {
			nodeMap[podID] = node{
				ID:      podID,
				Label:   row.PodName,
				Type:    "pod",
				Runtime: detectRuntime(row.PodName),
			}
		}
		if _, ok := nodeMap[secretID]; !ok {
			nodeMap[secretID] = node{
				ID:    secretID,
				Label: row.SecretName,
				Type:  "secret",
			}
		}

		edges = append(edges, edge{
			Source: podID,
			Target: secretID,
			Weight: row.RewriteCount,
		})
	}

	nodes := make([]node, 0, len(nodeMap))
	for _, n := range nodeMap {
		nodes = append(nodes, n)
	}
	if nodes == nil {
		nodes = []node{}
	}
	if edges == nil {
		edges = []edge{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(graphResponse{Nodes: nodes, Edges: edges})
}

func handleTopSecrets(w http.ResponseWriter, r *http.Request) {
	sql := `SELECT
    Attributes['secret_name'] as name,
    Attributes['secret_namespace'] as namespace,
    argMax(Value, TimeUnix) as total_rewrites
FROM otel.otel_metrics_sum
WHERE MetricName = 'kloak_tls_rewrite_total'
  AND Attributes['secret_name'] != ''
GROUP BY name, namespace
ORDER BY total_rewrites DESC
FORMAT JSONEachRow`

	body, err := queryClickHouse(clickhouseURL, sql)
	if err != nil {
		log.Printf("top-secrets query error: %v", err)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	var secrets []secretRow
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if line == "" {
			continue
		}
		var row secretRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			log.Printf("parse row error: %v", err)
			continue
		}
		secrets = append(secrets, row)
	}

	if secrets == nil {
		secrets = []secretRow{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topSecretsResponse{Secrets: secrets})
}

func main() {
	port := flag.Int("port", 8088, "HTTP port to listen on")
	flag.StringVar(&clickhouseURL, "clickhouse-url", "http://localhost:8123", "ClickHouse HTTP URL")
	flag.Parse()

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/api/graph", handleGraph)
	mux.HandleFunc("/api/top-secrets", handleTopSecrets)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("dashboard listening on %s (clickhouse: %s)", addr, clickhouseURL)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
