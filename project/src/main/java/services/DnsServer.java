package services;
import org.xbill.DNS.*;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class DnsServer extends Thread{
    private final DatagramSocket socket;
    private final String resultForAQuery;
    private String textChallenge;
    private volatile boolean running = true;

    public DnsServer(int port, String DNSServerAddress) throws SocketException {
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
                    response.addRecord(org.xbill.DNS.Record.fromString(request.getQuestion().getName(), Type.A, DClass.IN, 300, "host.docker.internal", Name.root), Section.ANSWER);
                } else if (type == Type.TXT) {
                    response.addRecord(org.xbill.DNS.Record.fromString(request.getQuestion().getName(), Type.TXT, DClass.IN, 300, textChallenge, Name.root), Section.ANSWER);
                }
                System.out.println(response);

                byte[] responseBytes = response.toWire(256);
                DatagramPacket responsePacket = new DatagramPacket(responseBytes, responseBytes.length, packet.getAddress(), packet.getPort());
                socket.send(responsePacket);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        socket.close();
    }

    public void setTextChallenge(String textChallenge) throws NoSuchAlgorithmException {
        this.textChallenge = textChallenge;
    }

    public void stopServer() {
        running = false;
        socket.close();
    }
}
