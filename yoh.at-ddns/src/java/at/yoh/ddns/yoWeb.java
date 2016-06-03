package at.yoh.ddns;

import java.util.ArrayList;
import java.util.List;

public class yoWeb {

	public void start() {
		
	}
	
	public void stop() {
		
	}
	
	public void restart() {
		
	}
	
	public SyncData sync(String cfgFile, String dataFile) {
		SyncData tag = new SyncData();
		tag.whole = true;
		tag.dataFile = dataFile;
		return tag;
	}
	
	public static class SyncData {
		
		public boolean whole = true;
		public String dataFile = "";
		public List<String> zoneNames = new ArrayList<String>();
		public List<String> zoneFiles = new ArrayList<String>();
		public List<Boolean> zoneDeleted = new ArrayList<Boolean>();
		
	}
	
}
