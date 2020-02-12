import java.util.Comparator;

import ghidra.app.plugin.processors.sleigh.Constructor;

public class SleighNode {
	private Constructor constructor;
	private int sons;
	
	public SleighNode(Constructor constructor, int sons) {
		this.constructor = constructor;
		this.sons = sons;
	}
	
	public int getSons() {
		return this.sons;
	}
	
	public Constructor getConstructor() {
		return this.constructor;
	}
}
