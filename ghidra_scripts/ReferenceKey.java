import java.util.Objects;

public class ReferenceKey {
	private final String fromAddress;
	private final String toAddress;
	
	public ReferenceKey(String from, String to) {
		this.fromAddress = from;
		this.toAddress = to;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj) return true;
		if(!(obj instanceof ReferenceKey)) return false;
		ReferenceKey key = (ReferenceKey) obj;
		return key.fromAddress.equals(fromAddress) && key.toAddress.equals(toAddress);
		
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(fromAddress, toAddress);
	}

}
