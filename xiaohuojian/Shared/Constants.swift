import Foundation

public enum XHJ {
    public static let appGroupID = "group.app.xiaohuojian.vpn"
    public static let appBundleID = "app.xiaohuojian.vpn"
    public static let tunnelBundleID = "app.xiaohuojian.vpn.tunnel"
    public static let displayName = "小火箭"
    public static let tunnelDescription = "小火箭"
    public static let storeFileName = "store.json"
    public static let tunnelConfigFileName = "tunnel-config.json"
    public static let singBoxFileName = "sing-box.json"
    public static let defaultsSuite = appGroupID

    public static let tunAddress = "198.18.0.1"
    public static let tunSubnet = "255.255.0.0"
    public static let tunDNSFallback = ["1.1.1.1", "8.8.8.8"]

    public enum DefaultsKey {
        public static let selectedNodeID = "selectedNodeID"
        public static let connectMode = "connectMode"
        public static let bypassLAN = "bypassLAN"
        public static let dnsMode = "dnsMode"
        public static let dnsServers = "dnsServers"
        public static let dohURL = "dohURL"
        public static let appearance = "appearance"
        public static let sessionUp = "traffic.session.up"
        public static let sessionDown = "traffic.session.down"
        public static let totalUp = "traffic.total.up"
        public static let totalDown = "traffic.total.down"
        public static let lastError = "lastTunnelError"
        public static let connectedAt = "connectedAt"
        public static let tunnelState = "tunnelState"
    }
}
