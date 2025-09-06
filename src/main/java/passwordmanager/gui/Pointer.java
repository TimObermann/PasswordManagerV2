package passwordmanager.gui;

public class Pointer {
    private int offset;
    private int length;

    public Pointer(int offset, int length) {
        this.offset = offset;
        this.length = length;
    }

    public int getOffset() {
        return offset;
    }

    public int getLength() {
        return length;
    }

    public void zero() {
        offset = -1;
        length = -1;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }
}
