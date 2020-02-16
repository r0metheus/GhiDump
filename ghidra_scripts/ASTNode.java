import java.util.ArrayList;
import java.util.List;

public class ASTNode {
	private String value;
	private String type;
	private ASTNode parent;
	private List<ASTNode> children = new ArrayList<>();
	
	public ASTNode(String value) {
		this.value = value;
		this.type = "None";
	}
	
	public ASTNode addChild(ASTNode child) {
		child.setParent(this);
		this.children.add(child);
		return child;
	}
	
	public void addChildren(List<ASTNode> children) {
		children.forEach(each -> each.setParent(this));
		this.children.addAll(children);
	}
	
	public List<ASTNode> getChildren() {
		return children;
	}
	
	public String getValue() {
		return value;
	}
	
	public void setValue(String value) {
		this.value = value;
	}
	
	public void setType(String type) {
	  this.type = type;
	}
	
	private void setParent(ASTNode parent) {
		this.parent = parent;
	}
	
	public ASTNode getParent() {
		return parent;
	}
	
	public String getType() {
	  return type;
	}
	
	public void deleteASTNode() {
		if(parent!=null) {
			int index = this.parent.getChildren().indexOf(this);
			this.parent.getChildren().remove(this);
			
			for(ASTNode node: getChildren())
				node.setParent(this.parent);
			
			this.parent.getChildren().addAll(index, this.getChildren());
		}
		
		this.getChildren().clear();
	}
	
	public boolean hasValue() {
		if(this.value.isEmpty() || this.value.isBlank() || this.value.equals(" "))
			return false;
		
		return true;		
	}
	
	public boolean hasChildren() {
		return !(this.children.isEmpty());
	}

}