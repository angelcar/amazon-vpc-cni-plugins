// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package plugin

import (
	"fmt"
	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/aws-service-connect/config"
	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ns"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"net"
	"strings"
)

const (
	// Names of iptables chains created for Service Connect rules.
	ingressChain = "SERVICE_CONNECT_INGRESS"
	egressChain  = "SERVICE_CONNECT_EGRESS"

	// zeroLengthIPString is what we expect net.IP.String() to return if the
	// ip has length 0. We use this to determing if an IP is empty.
	// Refer https://golang.org/pkg/net/#IP.String
	zeroLengthIPString = "<nil>"

	fileExistsErrMsg = "file exists"
)

// Add is the internal implementation of CNI ADD command.
func (plugin *Plugin) Add(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing ADD with netconfig: %+v.", netConfig)


	log.Infof("Creating veth pair for namespaces: %s <-> %s", args.Netns, netConfig.AppNetNSPath)
	appVeth, proxyVethInterfaceName, err := createVethPair(
		args.Netns, netConfig.AppNetNSPath, netConfig.MTU, args.IfName)
	if err != nil {
		return err
	}

	log.Infof("Created veth pair: proxyVethInterface=%s <-> appVethName=%s", proxyVethInterfaceName, appVeth)

	_, err = configureVethInterface(args.Netns, proxyVethInterfaceName, "20.0.2.1/24")
	if err != nil {
		return err
	}
	appLink, err := configureVethInterface(netConfig.AppNetNSPath, args.IfName, "20.0.2.2/24")
	if err != nil {
		return err
	}

	err = ns.WithNetNSPath(netConfig.AppNetNSPath, func(_ ns.NetNS) error {

		//routes, err := netlink.RouteList(appLink, netlink.FAMILY_ALL)
		//if err != nil {
		//	return errors.Wrapf(err, "bridge configure veth: unable to fetch routes for interface: %s", args.IfName)
		//}
		//
		//// Delete all default routes within the container
		//for _, route := range routes {
		//	if route.Gw == nil {
		//		err = netlink.RouteDel(&route)
		//		if err != nil {
		//			return errors.Wrapf(err,
		//				"bridge configure veth: unable to delete route: %v", route)
		//		}
		//	}
		//}

		gwIp := net.ParseIP("20.0.2.1")
		return ip.AddDefaultRoute(gwIp, appLink)
	})
	if err != nil {
		return err
	}


	// Add IP rules in the target network namespace.
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		var err error
		ipProtoMap := make(map[iptables.Protocol]string)
		ipProtoMap[iptables.ProtocolIPv4] = netConfig.EgressIgnoredIPv4s
		if netConfig.EnableIPv6 {
			ipProtoMap[iptables.ProtocolIPv6] = netConfig.EgressIgnoredIPv6s
		}

		for proto, ignoredIPs := range ipProtoMap {
			err = plugin.setupIptablesRules(proto, netConfig, ignoredIPs)
			if err != nil {
				log.Errorf("Failed to set up iptables rules: %v.", err)
				return err
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	// Pass through the previous result.
	log.Infof("Writing CNI result to stdout: %+v", netConfig.PrevResult)

	return cniTypes.PrintResult(netConfig.PrevResult, netConfig.CNIVersion)
}

// Del is the internal implementation of CNI DEL command.
// CNI DEL command can be called by the orchestrator multiple times for the same interface,
// and thus must be best-effort and idempotent.
func (plugin *Plugin) Del(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing DEL with netconfig: %+v.", netConfig)

	// Search for the target network namespace.
	ns, err := netns.GetNetNS(args.Netns)
	if err != nil {
		log.Errorf("Failed to find netns %s: %v.", args.Netns, err)
		return err
	}

	// Delete IP rules in the target network namespace.
	err = ns.Run(func() error {
		ipProtos := []iptables.Protocol{iptables.ProtocolIPv4}
		if netConfig.EnableIPv6 {
			ipProtos = append(ipProtos, iptables.ProtocolIPv6)
		}

		for _, proto := range ipProtos {
			err = plugin.deleteIptablesRules(proto, netConfig)
			if err != nil {
				log.Errorf("Failed to delete ip rules: %v.", err)
				return err
			}
		}

		return nil
	})

	return err
}

// setupIptablesRules sets iptables/ip6tables rules in container network namespace.
func (plugin *Plugin) setupIptablesRules(
	proto iptables.Protocol,
	config *config.NetConfig,
	egressIgnoredIPs string) error {

	return nil
	// Create a new iptables object.
	iptable, err := iptables.NewWithProtocol(proto)
	if err != nil {
		return err
	}

	err = plugin.setupIngressRules(iptable, config)
	if err != nil {
		return err
	}

	err = plugin.setupEgressRules(iptable, config, egressIgnoredIPs)
	if err != nil {
		return err
	}

	return nil
}

// setupEgressRules installs iptable rules to handle egress traffic.
func (plugin *Plugin) setupEgressRules(
	iptable *iptables.IPTables,
	config *config.NetConfig,
	egressIgnoredIPs string) error {

	// Create new chains.
	err := iptable.NewChain("nat", egressChain)
	if err != nil {
		return err
	}

	// Set up for outgoing traffic.
	if config.IgnoredUID != "" {
		err = iptable.Append("nat", egressChain, "-m", "owner", "--uid-owner", config.IgnoredUID, "-j", "RETURN")
		if err != nil {
			log.Errorf("Append rule for ignoredUID failed: %v", err)
			return err
		}
	}

	if config.IgnoredGID != "" {
		err = iptable.Append("nat", egressChain, "-m", "owner", "--gid-owner", config.IgnoredGID, "-j", "RETURN")
		if err != nil {
			log.Errorf("Append rule for ignoredGID failed: %v", err)
			return err
		}
	}

	if config.EgressIgnoredPorts != "" {
		err = iptable.Append("nat", egressChain, "-p", "tcp", "-m", "multiport", "--dports",
			config.EgressIgnoredPorts, "-j", "RETURN")
		if err != nil {
			log.Errorf("Append rule for egressIgnoredPorts failed: %v", err)
			return err
		}
	}

	if egressIgnoredIPs != "" {
		err = iptable.Append("nat", egressChain, "-p", "tcp", "-d", egressIgnoredIPs, "-j", "RETURN")
		if err != nil {
			log.Errorf("Append rule for egressIgnoredIPs failed: %v", err)
			return err
		}
	}

	// Redirect everything that is not ignored.
	err = iptable.Append("nat", egressChain, "-p", "tcp", "-j", "REDIRECT", "--to", config.ProxyEgressPort)
	if err != nil {
		log.Errorf("Append rule to redirect traffic to proxyEgressPort failed: %v", err)
		return err
	}

	// Apply egress chain to non local traffic.
	err = iptable.Append("nat", "OUTPUT", "-p", "tcp", "-m", "addrtype", "!", "--dst-type",
		"LOCAL", "-j", egressChain)
	if err != nil {
		log.Errorf("Append rule to jump from OUTPUT to egress chain failed: %v", err)
		return err
	}

	return nil
}

// setupIngressRules installs iptable rules to handle ingress traffic.
func (plugin *Plugin) setupIngressRules(
	iptable *iptables.IPTables,
	config *config.NetConfig) error {
	if config.ProxyIngressPort == "" || len(config.AppPorts) == 0 {
		return nil
	}

	err := iptable.NewChain("nat", ingressChain)
	if err != nil {
		return err
	}

	err = iptable.NewChain("mangle", ingressChain)
	if err != nil {
		return err
	}

	log.Infof("running iptables %s", strings.Join([]string{"nat", ingressChain, "-p", "tcp", "-m", "multiport", "--dports", config.AppPorts,
		"-j", "REDIRECT", "--to-port", config.ProxyIngressPort}, ","))

	// Route everything arriving at the application port to proxy.
	err = iptable.Append("nat", ingressChain, "-p", "tcp", "-m", "multiport", "--dports", config.AppPorts,
		"-j", "REDIRECT", "--to-port", config.ProxyIngressPort)
	if err != nil {
		log.Errorf("Append rule to redirect traffic to proxyIngressPort failed: %v", err)
		return err
	}

	log.Infof("running iptables %s", strings.Join([]string{"nat", "PREROUTING",  "-m", "addrtype", "!", "--src-type",
		"LOCAL", "-j", ingressChain}, ","))

	// Apply ingress chain to everything non-local.
	err = iptable.Append("nat", "PREROUTING",  "-m", "addrtype", "!", "--src-type",
		"LOCAL", "-j", ingressChain)
	if err != nil {
		log.Errorf("Append rule to jump from PREROUTING to ingress chain failed: %v", err)
		return err
	}

	log.Infof("running iptables %s", strings.Join([]string{"nat", "POSTROUTING",  "-o", "device", "-j", "MASQUERADE"}, ","))
	err = iptable.Append("nat", "POSTROUTING",  "-o", "device", "-j", "MASQUERADE")
	if err != nil {
		log.Errorf("Append rule to jump from POSTROUTING to ingress chain failed: %v", err)
		return err
	}

	return nil
}

// deleteIptablesRules deletes iptables/ip6tables rules in container network namespace.
func (plugin *Plugin) deleteIptablesRules(
	proto iptables.Protocol,
	config *config.NetConfig) error {
	/// Create a new iptables session.
	iptable, err := iptables.NewWithProtocol(proto)
	if err != nil {
		return err
	}

	err = plugin.deleteIngressRules(iptable, config)
	if err != nil {
		return err
	}

	err = plugin.deleteEgressRules(iptable)
	if err != nil {
		return err
	}

	return nil
}

// deleteIngressRules deletes the iptable rules for ingress traffic.
func (plugin *Plugin) deleteIngressRules(
	iptable *iptables.IPTables,
	config *config.NetConfig) error {
	if config.ProxyIngressPort == "" {
		return nil
	}
	// Delete ingress rule from iptables.
	err := iptable.Delete("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!", "--src-type",
		"LOCAL", "-j", ingressChain)
	if err != nil {
		log.Errorf("Delete the rule in PREROUTING chain failed: %v", err)
		return err
	}

	// flush and delete ingress chain.
	err = iptable.ClearChain("nat", ingressChain)
	if err != nil {
		log.Errorf("Failed to flush rules in chain[%v]: %v", ingressChain, err)
		return err
	}
	err = iptable.DeleteChain("nat", ingressChain)
	if err != nil {
		log.Errorf("Failed to delete chain[%v]: %v", ingressChain, err)
		return err
	}

	return nil
}

// deleteEgressRules deletes the iptable rules for egress traffic.
func (plugin *Plugin) deleteEgressRules(iptable *iptables.IPTables) error {
	// Delete egress rule from iptables.
	err := iptable.Delete("nat", "OUTPUT", "-p", "tcp", "-m", "addrtype", "!", "--dst-type",
		"LOCAL", "-j", egressChain)
	if err != nil {
		log.Errorf("Delete the rule in OUTPUT chain failed: %v", err)
		return err
	}

	// flush and delete egress chain.
	err = iptable.ClearChain("nat", egressChain)
	if err != nil {
		log.Errorf("Failed to flush rules in chain[%v]: %v", egressChain, err)
		return err
	}
	err = iptable.DeleteChain("nat", egressChain)
	if err != nil {
		log.Errorf("Failed to delete chain[%v]: %v", egressChain, err)
		return err
	}

	return nil
}

// TODO [angelcar]: All the below stuff was copied from ecs-bridge engine. Make them reusable instead of duplicating

// CreateVethPair creates the veth pair to attach the container to the bridge
func createVethPair(serviceConnectNetNsPath, appNetNsPath string, mtu int, interfaceName string) (*current.Interface, string, error) {
	// Find the application network namespace.
	log.Debugf("Searching for service connect netns %s.", serviceConnectNetNsPath)
	serviceConnectNetNs, err := ns.GetNS(serviceConnectNetNsPath)
	if err != nil {
		log.Errorf("Failed to find service connect netns %s: %v.",serviceConnectNetNsPath, err)
		return nil, "", err
	}

	createVethContext := newCreateVethPairContext(
		interfaceName, mtu, serviceConnectNetNs)

	err = ns.WithNetNSPath(appNetNsPath, createVethContext.run)
	if err != nil {
		return nil, "", err
	}

	return createVethContext.containerInterfaceResult, createVethContext.appVethName, nil
}


// createVethPairContext wraps the parameters and the method to create the
// veth pair to attach the container namespace to the bridge
type createVethPairContext struct {
	interfaceName string
	mtu           int
	// appVethName is set when the closure executes. Don't expect this
	// to be initialized
	appVethName string

	// serviceConnectNetNs is set when the closure executes. Don't expect this
	// to be initialized
	serviceConnectNetNs ns.NetNS

	// containerInterfaceResult is set when the closure executes. Don't
	// expect this to be initialized
	containerInterfaceResult *current.Interface
}

func newCreateVethPairContext(interfaceName string, mtu int, serviceConnectNetNs ns.NetNS) *createVethPairContext {

	return &createVethPairContext{
		interfaceName: interfaceName,
		mtu:           mtu,
		serviceConnectNetNs: serviceConnectNetNs,
	}
}

// run defines the closure to execute within the container's namespace to
// create the veth pair
func (createVethContext *createVethPairContext) run(_ ns.NetNS) error {

	log.Infof("Service Connect NetNS: %s", createVethContext.serviceConnectNetNs.Path())

	appVeth, proxyVeth, err := ip.SetupVeth(
		createVethContext.interfaceName, createVethContext.mtu, createVethContext.serviceConnectNetNs)
	if err != nil {
		return errors.Wrapf(err,
			"bridge create veth pair: unable to setup veth pair for interface: %s",
			createVethContext.interfaceName)
	}

	createVethContext.appVethName = appVeth.Name

	createVethContext.containerInterfaceResult = &current.Interface{
		Name: proxyVeth.Name,
		Mac:  proxyVeth.HardwareAddr.String(),
	}
	return nil
}



// configureVethContext wraps the parameters and the method to configure the
// veth interface in container's namespace
type configureVethContext struct {
	interfaceName string
	ipNetStr string
	link netlink.Link
}

// configureVethInterface configures the container's veth interface,
// including setting up routes within the container
func configureVethInterface(netnsName, interfaceName, ipNetStr string) (netlink.Link, error) {
	configureContext := newConfigureVethContext(interfaceName, ipNetStr)
	err := ns.WithNetNSPath(netnsName, configureContext.run)
	return configureContext.link, err
}

func newConfigureVethContext(interfaceName, ipNetStr string) *configureVethContext {
	return &configureVethContext{
		interfaceName: interfaceName,
		ipNetStr:ipNetStr,
	}
}

// run defines the closure to execute within the container's namespace to
// configure the veth interface
func (cvctx *configureVethContext) run(_ ns.NetNS) error {
	link, err := netlink.LinkByName(cvctx.interfaceName)
	if err != nil {
		return errors.Wrapf(err,
			"bridge configure veth: unable to get link for interface: %s",
			cvctx.interfaceName)
	}

	cvctx.link = link

	if err := netlink.LinkSetUp(cvctx.link); err != nil {
		return fmt.Errorf("failed to set %q UP: %v", cvctx.interfaceName, err)
	}


	ipNet, err := netlink.ParseIPNet(cvctx.ipNetStr)
	if err != nil {
		return err
	}
	addr := &netlink.Addr{IPNet:ipNet , Label: ""}
	if err = netlink.AddrAdd(cvctx.link, addr); err != nil {
		return fmt.Errorf("failed to add IP addr %v to %q: %v", cvctx.ipNetStr, cvctx.interfaceName, err)
	}



	// Generate and set the hardware address for the interface, given
	// its IP
	err = ip.SetHWAddrByIP(
		cvctx.interfaceName, ipNet.IP, nil)
	if err != nil {
		return errors.Wrapf(err,
			"bridge configure veth: unable to set hardware address for interface: %s",
			cvctx.interfaceName)
	}

	return nil
}