package passwordmanager.gui;

public class RadixTree {

    public static class Node {
        private char[] val;
        private java.util.HashMap<CharArray, Node> edges;
        private Pointer ptr;

        public Node() {
            val = null;
            edges = new java.util.HashMap<>();
            ptr = null;
        }

        public Node(char[] val, Pointer p) {
            edges = new java.util.HashMap<>();
            this.val = val;
            ptr = p;
        }

        public void addEdge(char[] edge, Node child) {
            edges.put(new CharArray(edge), child);
        }

        public void zeroSubtree() {
            if(!edges.isEmpty()) {

                java.util.List<CharArray> pointerSet = new java.util.ArrayList<>(edges.keySet());

                for (Node n : edges.values()) {
                    n.zeroSubtree();
                }

                edges.clear();

                for (CharArray a : pointerSet) {
                    a.zero();
                }

            }

            if(val != null) GUI_Util.zeroArray(val);
            if(ptr != null ) ptr.zero();
        }

        public char[] getVal() {
            return val;
        }

        public java.util.HashMap<CharArray, Node> getEdges() {
            return edges;
        }
    }
    public static class CharArray {
        private char[] array;

        public CharArray(char[] a) {
            array = new char[a.length];
            System.arraycopy(a, 0, array, 0, a.length);
        }

        public CharArray(char[] a, int from, int to) {
            array = new char[to - from];
            System.arraycopy(a, from, array, 0, to - from);
        }

        public void zero() {
            GUI_Util.zeroArray(array);
            array = null;
        }

        public static CharArray of(char[] a) {
            return new CharArray(a);
        }

        public static CharArray of(char[] a, int from, int to) {
            return new CharArray(a, from, to);
        }

        @Override
        public boolean equals(Object obj) {
            if(obj instanceof CharArray) {

                return GUI_Util.safeCmp(array, ((CharArray) obj).array);

            }
            return false;
        }

        @Override
        public int hashCode() {
            return java.util.Arrays.hashCode(array);
        }

        private boolean isWholePrefixOf(char[] a) {
            if(a.length < array.length) return false;
            return commonPrefixLen(a) == array.length;
        }

        private boolean isWholePrefixOf(CharArray a) {
            return isWholePrefixOf(a.array);
        }

        private int commonPrefixLen(char[] b) {
            char[] longer = array.length > b.length ? array : b;
            char[] shorter = array.length <= b.length ? array : b;

            for (int i = 0; i < shorter.length; i++) {
                if(shorter[i] != longer[i]) return i;
            }

            return shorter.length;
        }

        public char[] getArray() {
            return array;
        }
    }
    private record PrefixSearchResult(Node node, char[] prefix){}

    private final Node root;

    public RadixTree() {
        root = new Node();
    }

    public void delete(char[] word) {
        if (word == null || word.length == 0) {
            return;
        }
        delete(root, word);
    }

    private boolean delete(Node node, char[] remainingWord) {
        for (CharArray edge : node.edges.keySet()) {
            Node child = node.edges.get(edge);

            int cpl = edge.commonPrefixLen(remainingWord);

            if (cpl == edge.array.length && cpl <= remainingWord.length) {

                char[] nextRemainingWord = GUI_Util.subarray(remainingWord, cpl, remainingWord.length);

                if (nextRemainingWord.length > 0) {

                    if (delete(child, nextRemainingWord)) {

                        if (child.ptr == null && child.edges.size() == 1) {
                            CharArray grandChildEdge = child.edges.keySet().iterator().next();
                            Node grandChild = child.edges.get(grandChildEdge);

                            char[] newEdgeChars = GUI_Util.merge(edge.getArray(), grandChildEdge.getArray());
                            CharArray newEdge = new CharArray(newEdgeChars);

                            node.edges.remove(edge);
                            node.edges.put(newEdge, grandChild);

                            return false;
                        }
                        return true;
                    }
                    return false;
                }
                else {
                    if (!child.edges.isEmpty()) {
                        child.ptr = null;
                    } else {
                        node.edges.remove(edge);
                    }

                    return true;
                }
            }
        }

        return false;
    }

    public java.util.List<String> query(char[] prefix) {
        java.util.List<String> result = new java.util.ArrayList<>();

        if(prefix == null) {
            return result;
        }

        PrefixSearchResult searchResult = findNodeForPrefix(root, prefix, new char[0]);
        if(searchResult == null) {
            return result;
        }

        collectAllWords(searchResult.node, searchResult.prefix, result);

        return result;
    }

    public java.util.List<String> getAllWords() {
        java.util.Set<CharArray> set = collectAllEntries().keySet();
        return set.stream().map(c -> new String(c.array)).toList();
    }
    private void collectAllWords(Node node, char[] prefix, java.util.List<String> results) {
        if(node.ptr != null) results.add(new String(prefix));

        for (CharArray edge : node.edges.keySet()) {
            Node child = node.edges.get(edge);
            collectAllWords(child, GUI_Util.merge(prefix, edge.array), results);
        }
    }

    public java.util.Map<CharArray, Pointer> collectAllEntries() {
        java.util.Map<CharArray, Pointer> nodes = new java.util.HashMap<>();

        collectAllFinalNodes(root, new char[0], nodes);

        return nodes;
    }
    private void collectAllFinalNodes(Node node, char[] word, java.util.Map<CharArray, Pointer> nodes) {
        if(node.ptr != null) {
            nodes.put(CharArray.of(word), node.ptr);
        }

        for (CharArray edge : node.edges.keySet()) {
            collectAllFinalNodes(node.edges.get(edge), GUI_Util.merge(word, edge.array), nodes);
        }
    }
    private PrefixSearchResult findNodeForPrefix(Node node, char[] remainingPrefix, char[] acc) {
        if(remainingPrefix.length == 0) {
            return new PrefixSearchResult(node, acc);
        }

        CharArray remain = new CharArray(remainingPrefix);

        for (CharArray edge : node.edges.keySet()) {
            Node child = node.edges.get(edge);

            if(edge.isWholePrefixOf(remain)) {
                char[] remainingPrePrefix = GUI_Util.subarray(remain.array, edge.array.length, remainingPrefix.length);
                remain.zero();

                return findNodeForPrefix(child, remainingPrePrefix, GUI_Util.merge(acc, edge.array));
            }

            if(remain.isWholePrefixOf(edge)) {
                remain.zero();

                return new PrefixSearchResult(child, GUI_Util.merge(acc, remainingPrefix));
            }
        }

        return null;
    }

    public Pointer lookup(char[] word) {
        if(word == null || word.length == 0) return null;
        return lookup(root, word);
    }
    private Pointer lookup(Node node, char[] word) {
        for (CharArray edge : node.edges.keySet()) {
            Node child = node.edges.get(edge);

            int d = edge.commonPrefixLen(word);

            if(d == 0) continue;
            if(d == edge.array.length) {
                if(edge.array.length == word.length) {
                    return child.ptr;
                }

                char[] remainingWord = GUI_Util.subarray(word, edge.array.length, word.length);
                return lookup(child, remainingWord);
            }
        }

        return null;
    }

    public void insert(char[] word, Pointer ptr) {
        insert(root, word, ptr);
    }
    private void insert(Node root, char[] w, Pointer ptr) {

        if(w.length == 0) {
            root.ptr = ptr;
            return;
        }

        for (CharArray edge : root.edges.keySet()) {
            Node child = root.edges.get(edge);

            int cpl = edge.commonPrefixLen(w);

            if(cpl == 0) {
               continue;
            }

            if(cpl < edge.array.length) {
                CharArray commonPrefix = CharArray.of(edge.array, 0, cpl);
                CharArray remainingEdge = CharArray.of(edge.array, cpl, edge.array.length);
                CharArray remainingWord = CharArray.of(w, cpl, w.length);

                Node intermediate = new Node(commonPrefix.array, null);
                root.edges.remove(edge);
                root.edges.put(commonPrefix, intermediate);

                child.val = remainingEdge.array;
                intermediate.edges.put(remainingEdge, child);

                if(remainingWord.array.length > 0) {
                    Node newSubNode = new Node(remainingEdge.array, ptr);
                    intermediate.edges.put(remainingWord, newSubNode);
                }
                else {
                    intermediate.ptr = ptr;
                }

                return;
            }

            char[] remainingWord = GUI_Util.subarray(w, cpl, w.length);
            insert(child, remainingWord, ptr);
            return;
        }

        CharArray word = new CharArray(w);
        Node n = new Node(w, ptr);
        root.edges.put(word, n);
    }

    public void zero() {
        root.zeroSubtree();
    }

}
