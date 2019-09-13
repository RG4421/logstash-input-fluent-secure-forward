package com.onemainfinancial.logstash.plugins.fluent;

import com.google.gson.Gson;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.msgpack.MessagePack;
import org.msgpack.MessageTypeException;
import org.msgpack.type.ArrayValue;
import org.msgpack.type.Value;
import org.msgpack.type.ValueType;
import org.msgpack.unpacker.BufferUnpacker;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static com.onemainfinancial.logstash.plugins.fluent.Utils.*;

public class FluentSession implements Runnable {
    private static final String REMOVE_HOST_CLOSED_MESSAGE = "Remote host closed connection during handshake";
    private static final Logger logger = LogManager.getLogger(FluentSession.class);
    private byte[] sharedKeyNonce = generateSalt();
    private byte[] authKeySalt = generateSalt();
    private Socket session;
    private OutputStream outputStream;
    private InputStream inputStream;
    private Gson gson = new Gson();
    private MessagePack messagePack = new MessagePack();
    private FluentSecureForward parent;

    FluentSession(FluentSecureForward parent, Socket socket) {
        logger.debug("Received connection {}", socket.getRemoteSocketAddress());
        this.parent = parent;
        this.session = socket;
    }

    private void sendPong(boolean authenticated, Object errorReasonOrSalt) throws IOException {
        List<Object> list = new ArrayList<>();
        list.add("PONG");
        list.add(authenticated);
        if (!authenticated) {
            list.add(errorReasonOrSalt);
            list.add("");
            list.add("");
        } else {
            list.add("");
            list.add(parent.selfHostname);
            list.add(getHexDigest((byte[]) errorReasonOrSalt, parent.selfHostnameBytes, sharedKeyNonce, parent.sharedKeyBytes));
        }
        sendData(messagePack.write(list));
    }

    private void sendHello() throws IOException {
        List<Object> list = new ArrayList<>();
        Map<String, Object> opts = new HashMap<>();
        opts.put("nonce", sharedKeyNonce);
        opts.put("auth", parent.requireAuthentication ? authKeySalt : "");
        opts.put("keepalive", parent.enableKeepalive);
        list.add("HELO");
        list.add(opts);
        sendData(messagePack.write(list));
    }

    private Object[] checkPing(ArrayValue value) {
        if (value.size() != 6) {
            return new Object[]{false, "invalid ping message"};
        }
        byte[] hostname = value.get(1).asRawValue().getByteArray();
        byte[] sharedKeySalt = value.get(2).asRawValue().getByteArray();
        String sharedKeyHexDigest = asString(value.get(3));
        String username = asString(value.get(4)).toLowerCase();
        byte[] usernameBytes = value.get(4).asRawValue().getByteArray();
        if (!getHexDigest(
                sharedKeySalt,
                hostname,
                sharedKeyNonce,
                parent.sharedKeyBytes)
                .equals(sharedKeyHexDigest)) {
            return new Object[]{false, "sharedKey mismatch"};
        } else if (parent.requireAuthentication && !(parent.users.containsKey(username) && getHexDigest(
                authKeySalt,
                usernameBytes,
                parent.users.get(username).getBytes())
                .equals(asString(value.get(5))))) {
            return new Object[]{false, "username/password mismatch"};
        }
        return new Object[]{true, sharedKeySalt};
    }

    private void sendData(byte[] bytes) throws IOException {
        outputStream.write(bytes);
        outputStream.flush();
    }

    @SuppressWarnings("unchecked")
    private void decodeEvent(Value value) {
        try {
            ValueType valueType = value.getType();
            //the first output_tag event comes in as [output_tag,stringEncodedMessagePack]
            if (valueType.equals(ValueType.RAW)) {
                try (BufferUnpacker bufferUnpacker = messagePack.createBufferUnpacker(value.asRawValue().getByteArray())) {
                    bufferUnpacker.forEach(this::decodeEvent);
                }
            } else if (valueType.equals(ValueType.ARRAY)) {
                //[timestamp,data]
                decodeEvent(value.asArrayValue().get(1));
            } else if (valueType.equals(ValueType.MAP)) {
                //convert value to map and consume it
                parent.consumer.accept(gson.fromJson(value.asMapValue().toString(), Map.class));
            }
        } catch (Exception e) {
            logger.error("Could not decode event", e);
        }
    }


    private void readFromSession() throws IOException {
        while (true) {
            try {
                ArrayValue arrayValue = messagePack
                        .read(inputStream)
                        .asArrayValue();
                String messageType = asString(arrayValue.get(0));
                if (messageType.equals("PING")) {
                    Object[] result = checkPing(arrayValue);
                    boolean successfullyAuthenticated = (boolean) result[0];
                    sendPong(successfullyAuthenticated, result[1]);
                    if (!successfullyAuthenticated) {
                        break;
                    }
                } else if (messageType.equals("output_tag")) {
                    decodeEvent(arrayValue.get(1));
                } else {
                    logger.debug("Received unknown message type of {} from {}", messageType, session.getRemoteSocketAddress());
                }
            } catch (MessageTypeException e) {
                logger.error("Invalid payload read from " + session.getRemoteSocketAddress(), e);
            }
        }
    }

    public void run() {
        try {
            if (session instanceof SSLSocket) {
                ((SSLSocket) session).startHandshake();
            }
            outputStream = session.getOutputStream();
            inputStream = session.getInputStream();
            sendHello();
            readFromSession();
        } catch (EOFException e) {
            logger.debug("Socket {} closed", session.getRemoteSocketAddress());
        } catch (SSLHandshakeException e){
            if(e.getMessage().equalsIgnoreCase(REMOVE_HOST_CLOSED_MESSAGE)){
                logger.trace("Suppressed exception from socket",e);
            }else{
                logger.error("Caught SSLHandshakeException from socket " + session.getRemoteSocketAddress(), e);
            }
        } catch (IOException e) {
            logger.error("Caught exception from socket " + session.getRemoteSocketAddress(), e);
        }
        try {
            session.close();
        } catch (Exception e) {
            //no-op
        }
    }
}