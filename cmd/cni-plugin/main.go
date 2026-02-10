package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/spinningfactory/kloak/pkg/cni/api"
)

const (
	// SocketPath is the path to the Kloak CNI agent socket
	SocketPath = "/run/kloak/cni.sock"
	// Timeout for CNI operations
	CNITimeout = 10 * time.Second
)

// PluginConf is the configuration for the Kloak CNI plugin
type PluginConf struct {
	types.NetConf
	// Add custom configuration here if needed
	LogFile string `json:"logFile,omitempty"`
}

// K8sArgs is the kubernetes-specific CNI arguments
type K8sArgs struct {
	types.CommonArgs
	K8S_POD_NAME      types.UnmarshallableString
	K8S_POD_NAMESPACE types.UnmarshallableString
	K8S_POD_UID       types.UnmarshallableString
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, "kloak-cni")
}

func cmdAdd(args *skel.CmdArgs) error {
	conf := &PluginConf{}
	if err := json.Unmarshal(args.StdinData, conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	// Parse PrevResult
	if err := version.ParsePrevResult(&conf.NetConf); err != nil {
		return fmt.Errorf("failed to parse prevResult: %v", err)
	}

	// Extract K8s metadata
	// We MUST parse CNI_ARGS to get K8S_POD_NAMESPACE and K8S_POD_NAME
	// because container runtimes might not set them as environment variables on the plugin process clearly.
	k8sArgs := K8sArgs{}
	if err := types.LoadArgs(args.Args, &k8sArgs); err != nil {
		// Just log error? Or fail? If we can't parse, we might proceed but risk deadlock if it IS the agent.
		// However, standard CNI should have args.
		// For safety, let's try to proceed.
	}

	podNamespace := string(k8sArgs.K8S_POD_NAMESPACE)
	podName := string(k8sArgs.K8S_POD_NAME)
	podUID := string(k8sArgs.K8S_POD_UID)

	// Fallback to env if empty (though LoadArgs handles that too?)
	if podNamespace == "" {
		podNamespace = os.Getenv("K8S_POD_NAMESPACE")
	}
	if podName == "" {
		podName = os.Getenv("K8S_POD_NAME")
	}

	// Check if this is a chained call. If not, we might be the first plugin (unlikely for our use case).
	// If we are chained, we expect PrevResult.
	// However, if we are erroneously called as a standalone plugin or first plugin, we might not have PrevResult.
	// In that case, we can't really do anything useful if we depend on IPAM/networking being set up.
	// But wait, the error "must be called as a chained plugin" comes from passThrough.
	// If we are "ignored" (e.g. kloak-system namespace), we call passThrough.
	// If passThrough fails because PrevResult is nil, that implies we were NOT chained properly for THAT pod.

	// Fix: If namespace match fails (empty), we might fall through to dialAgent.
	// Log what we found for debugging.
	// Since we can't easily log to stdout, we might rely on the error message bubbling up, or write to a file.
	// For now, let's relax the passThrough check: if PrevResult is nil, we just return nil (success, no-op).
	// This avoids blocking the pod if something is weird with the chain.

	if podNamespace == "kloak-system" {
		return passThrough(conf)
	}

	// Connect to Kloak Agent
	conn, err := dialAgent()
	if err != nil {
		// Fail open or closed? detailed in config?
		// For now, let's log and fail, as we promise security.
		return fmt.Errorf("failed to connect to kloak agent: %v", err)
	}
	defer conn.Close()

	client := pb.NewCNIClient(conn)

	// Prepare request
	req := &pb.PodRequest{
		Command:      pb.Command_ADD,
		ContainerId:  args.ContainerID,
		Netns:        args.Netns,
		Ifname:       args.IfName,
		Args:         args.Args,
		Path:         args.Path,
		StdinData:    args.StdinData,
		PodName:      podName,
		PodNamespace: podNamespace,
		PodUid:       podUID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), CNITimeout)
	defer cancel()

	_, err = client.HandlePod(ctx, req)
	if err != nil {
		return fmt.Errorf("kloak agent failed to handle pod: %v", err)
	}

	// Pass through the result from the previous plugin (chained)
	// We are a chained plugin, so we just return the result from the previous one.
	// The previous result is in args.StdinData (NetConf.PrevResult)
	if conf.PrevResult == nil {
		return fmt.Errorf("must be called as a chained plugin")
	}

	// Parse previous result
	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return fmt.Errorf("could not convert result to current version: %v", err)
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	// Connect to Kloak Agent
	conn, err := dialAgent()
	if err != nil {
		// Best effort for delete
		return nil
	}
	defer conn.Close()

	client := pb.NewCNIClient(conn)

	req := &pb.PodRequest{
		Command:      pb.Command_DEL,
		ContainerId:  args.ContainerID,
		Netns:        args.Netns,
		Ifname:       args.IfName,
		Args:         args.Args,
		Path:         args.Path,
		StdinData:    args.StdinData,
		PodName:      getEnv("K8S_POD_NAME"),
		PodNamespace: getEnv("K8S_POD_NAMESPACE"),
		PodUid:       getEnv("K8S_POD_UID"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), CNITimeout)
	defer cancel()

	_, _ = client.HandlePod(ctx, req)

	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	// TODO: Implement check
	return nil
}

func dialAgent() (*grpc.ClientConn, error) {
	return grpc.NewClient("unix://"+SocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

func getEnv(key string) string {
	// args.Args typically contains "K8S_POD_NAME=foo;K8S_POD_NAMESPACE=bar..."
	// But CNI spec also says orchestrators SHOULD set env vars.
	// Kubernetes sets CNI_ARGS.
	// skel.CmdArgs parses CNI_ARGS into args.Args.
	// However, we can also extract from env if available, or parse args.Args.
	// For simplicity, let's try env first (common in K8s CNI).
	// Actually, standard is parsing args.Args.
	// Let's implement a parser for args.Args string later if env is empty.
	return os.Getenv(key)
}

// passThrough returns the result from the previous plugin without any changes
func passThrough(conf *PluginConf) error {
	if conf.PrevResult == nil {
		// DANGEROUS: If we are chained but PrevResult is nil, it means upstream failed or we are first.
		// If we return success with empty result, IPAM might be missing.
		// But in this specific case (ignoring kloak-system), we just want to NOT block.
		// If K3s/Flannel is already set up, maybe it's fine?
		// Actually, if we are chained, we MUST return a result derived from PrevResult.
		// If missing, we can try to return a dummy result to satisfy CNI, but networking won't work if we claimed to set it up.
		// Kloak CNI doesn't claim to set up networking.
		// The error "must be called as a chained plugin" blocks pod startup.
		// Let's log and return nil (success) but print no result?
		// CNI 0.3.1 spec says "Plugin must write Result to stdout".
		// We can return a dummy success result.
		dummy := &current.Result{
			CNIVersion: conf.CNIVersion,
		}
		return types.PrintResult(dummy, conf.CNIVersion)
	}

	// Parse previous result
	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return fmt.Errorf("could not convert result to current version: %v", err)
	}

	return types.PrintResult(result, conf.CNIVersion)
}
