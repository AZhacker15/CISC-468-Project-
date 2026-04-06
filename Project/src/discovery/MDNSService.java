package discovery;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;
import javax.jmdns.ServiceEvent;

import java.net.InetAddress;

public class MDNSService {

    private int port;
    private JmDNS jmdns;

    public MDNSService(int port) {
        this.port = port;
    }

    public void registerService() throws Exception {
        jmdns = JmDNS.create(InetAddress.getLocalHost());

        ServiceInfo serviceInfo = ServiceInfo.create(
                "_p2p._tcp.local.",
                "PeerNode-" + port,
                port,
                "Secure P2P File Sharing"
        );

        jmdns.registerService(serviceInfo);

        System.out.println("mDNS service registered on port " + port);
    }

    public void discoverPeers() throws Exception {

        if (jmdns == null) {
            jmdns = JmDNS.create(InetAddress.getLocalHost());
        }

        jmdns.addServiceListener("_p2p._tcp.local.", new ServiceListener() {

            @Override
            public void serviceAdded(ServiceEvent event) {
                jmdns.requestServiceInfo(event.getType(), event.getName());
            }

            @Override
            public void serviceRemoved(ServiceEvent event) {
                System.out.println("Peer left: " + event.getName());
            }

            @Override
            public void serviceResolved(ServiceEvent event) {
                ServiceInfo info = event.getInfo();

                String name = info.getName();
                String host = info.getHostAddresses()[0];
                int port = info.getPort();

                System.out.println("Discovered peer:");
                System.out.println("  Name: " + name);
                System.out.println("  Address: " + host + ":" + port);
            }
        });

        System.out.println("Started peer discovery...");
    }
}