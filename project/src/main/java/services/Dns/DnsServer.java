package services.Dns;
import org.xbill.DNS.*;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class DnsServer extends Thread{
    private final DatagramSocket socket;
    private final String resultForAQuery;
    private Map<String, String> textChallenge = new HashMap<>();
    private volatile boolean running = true;

    public DnsServer(String DNSServerAddress) throws SocketException {
        this.socket = new DatagramSocket(new InetSocketAddress(10053));
        resultForAQuery = DNSServerAddress;
    }

    @Override
    public void run() {
        while (running) {
            byte[] buf = new byte[512];
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(packet);
                Message request = new Message(buf);
                int type = request.getQuestion().getType();
                Header header = new Header(request.getHeader().getID());
                header.setFlag(Flags.RA);
                header.setFlag(Flags.QR);
                header.setFlag(Flags.AA);
                Message response = new Message();
                response.setHeader(header);
                response.addRecord(request.getQuestion(), Section.QUESTION);
                if (type == Type.A) {
                    response.addRecord(org.xbill.DNS.Record.fromString(request.getQuestion().getName(), Type.A, DClass.IN, 300, resultForAQuery, Name.root), Section.ANSWER);
                } else if (type == Type.TXT) {
                    if (textChallenge.get(request.getQuestion().getName().toString()) != null){
                    if (!textChallenge.get(request.getQuestion().getName().toString()).isBlank())
                        response.addRecord(org.xbill.DNS.Record.fromString(request.getQuestion().getName(), Type.TXT, DClass.IN, 300, textChallenge.get(request.getQuestion().getName().toString()), Name.root), Section.ANSWER);
                }}
                byte[] responseBytes = response.toWire(256);
                DatagramPacket responsePacket = new DatagramPacket(responseBytes, responseBytes.length, packet.getAddress(), packet.getPort());
                socket.send(responsePacket);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        socket.close();
    }

    public void setTextChallenge(String a, String b) {
        this.textChallenge.clear();
        this.textChallenge.put(a, b);
    }

    public void stopServer() {
        running = false;
        socket.close();
    }
}
