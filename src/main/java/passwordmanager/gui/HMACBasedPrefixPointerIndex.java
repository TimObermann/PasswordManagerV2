package passwordmanager.gui;

import passwordmanager.crypt.hash.SHA2;
import passwordmanager.crypt.mac.HMAC;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class HMACBasedPrefixPointerIndex {

    static class Node {

        private byte[] hash;
        private ArrayList<NodeKey> refrences;
        private boolean isEnd;
        private int offset;
        private int length;

        public Node(byte[] data, int offset, int length) {
            this.hash = data;
            this.refrences = new ArrayList<>();

            this.isEnd = true;
            this.offset = offset;
            this.length = length;
        }

        public Node(byte[] data, ArrayList<NodeKey> refrences) {
            this.hash = data;
            this.refrences = refrences;

            this.isEnd = false;
            this.offset = -1;
            this.length = -1;
        }

        public Node(byte[] data) {
            this.hash = data;
            refrences = new ArrayList<>();

            this.isEnd = false;
            this.offset = -1;
            this.length = -1;
        }

        private Node() {}

        public int size() {
            return 4 + 1 + hash.length + 4 + (refrences.size() * hash.length) + (isEnd ? 8 : 0);
        }

        public static Node deserialize(byte[] data) {
            Node n = new Node();
            int offset = 4;

            n.isEnd = data[offset++] == (byte)1;
            byte[] hash = new byte[hmac.getHashingAlgorithm().getDigestSize()];
            System.arraycopy(data, offset, hash, 0, hash.length);

            n.hash = hash;
            offset += hash.length;

            byte[] intbuff = new byte[4];
            System.arraycopy(data, offset, intbuff, 0, 4);

            int refNum = GUI_Util.toInt(intbuff);
            offset += 4;

            ArrayList<NodeKey> references = new ArrayList<>();

            byte[] hash_ref = new byte[hmac.getHashingAlgorithm().getDigestSize()];


            for (int i = 0; i < refNum; i++) {
                System.arraycopy(data, offset, hash_ref, 0, hash_ref.length);
                references.add(new NodeKey(hash_ref));
                offset += hash_ref.length;
            }

            n.refrences = references;

            if(n.isEnd) {
                System.arraycopy(data, offset, intbuff, 0, 4);
                n.offset = GUI_Util.toInt(intbuff);
                System.arraycopy(data, offset + 4, intbuff, 0, 4);
                n.length = GUI_Util.toInt(intbuff);
            }
            else {
                n.offset = -1;
                n.length = -1;
            }

            return n;
        }

        public byte[] serialize() {
            byte[] ser = new byte[size()];
            int offset = 0;

            System.arraycopy(GUI_Util.toBytes(size()), 0, ser, offset, 4);
            offset += 4;

            ser[offset++] = (byte) (isEnd ? 1 : 0);

            System.arraycopy(hash, 0, ser, offset, hash.length);
            offset += hash.length;

            System.arraycopy(GUI_Util.toBytes(refrences.size()), 0, ser, offset, 4);
            offset += 4;

            for (NodeKey n : refrences) {
                System.arraycopy(n.data, 0, ser, offset, n.data.length);
                offset += n.data.length;
            }

            if(isEnd) {
                System.arraycopy(GUI_Util.toBytes(this.offset), 0, ser, offset, 4);
                offset += 4;

                System.arraycopy(GUI_Util.toBytes(length), 0, ser, offset, 4);
            }

            return ser;
        }
    }
    static class NodeKey {
        private final byte[] data;

        public NodeKey(byte[] data) {
            this.data = new byte[data.length];
            System.arraycopy(data, 0, this.data, 0, data.length);
        }

        @Override
        public boolean equals(Object obj) {
            if(obj instanceof NodeKey) {
                byte[] other = ((NodeKey) obj).getData();

                int d = 0;
                d |= other.length - data.length;

                for (int i = 0; i < data.length; i++) {
                    d |= other[i] ^ data[i];
                }

                return d == 0;

            }

            return false;
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(data);
        }

        public byte[] getData() {
            return data;
        }
    }

    private final HashMap<NodeKey, Node> cache;
    private final byte[] key;
    private static final HMAC hmac = new HMAC(new SHA2());
    private int serialized_size;

    public HMACBasedPrefixPointerIndex(byte[] key) {
        cache = new HashMap<>();
        this.key = key;
        serialized_size = 0;
    }

    public void add(char[] message, int offset, int length) {

        byte[] hashed = hmac.generateTag(GUI_Util.toBytes(message, 0, message.length), key);
        Node toAdd = new Node(hashed, offset, length);
        NodeKey toAddKey = new NodeKey(hashed);

        if(cache.containsKey(toAddKey)) {
            return;
        }

        cache.put(toAddKey, toAdd);

        for (int i = message.length - 1; i >= 1; i--) {
            hashed = hmac.generateTag(GUI_Util.toBytes(message, 0, i), key);
            NodeKey entry = new NodeKey(hashed);

            if(cache.containsKey(entry)) {
                cache.get(entry).refrences.add(toAddKey);
                serialized_size += toAddKey.data.length;
            }
            else {
                Node intermediate = new Node(hashed);
                intermediate.refrences.add(toAddKey);
                cache.put(entry, intermediate);

                serialized_size += intermediate.size();
            }
        }
    }

    public void deserialize(byte[] data) {
        int offset = 0;

        byte[] intBuff = new byte[4];

        while (offset < data.length) {
            System.arraycopy(data, offset, intBuff,0 , 4);
            int currNodeLen = GUI_Util.toInt(intBuff);
            offset += 4;

            if(currNodeLen + offset > data.length) {
                throw new IllegalArgumentException();
            }

            byte[] buff = new byte[currNodeLen];
            System.arraycopy(data, offset, buff, 0, currNodeLen);
            offset += currNodeLen;

            Node n = Node.deserialize(buff);
            NodeKey nKey = new NodeKey(n.hash);

            cache.put(nKey, n);
        }

    }

    public int getSerializedSize() {
        return serialized_size;
    }

    public byte[] serialize() {
        byte[] ser = new byte[serialized_size];

        int offset = 0;
        for (Node n : cache.values()) {
            System.arraycopy(n.serialize(), 0, ser, offset, n.size());
            offset += n.size();
        }

        return ser;
    }




}