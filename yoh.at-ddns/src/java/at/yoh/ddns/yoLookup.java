/*
 * 
 * Developed by Tran Dinh Thoai <codingore@gmail.com> [ codingore.blogspot.com ]
 * 
 */

package at.yoh.ddns;

import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import at.yoh.ddns.DNS.Lookup;

public class yoLookup {

	public static String CFG_FILE = "";
	
	public static void main(String[] args) throws Exception {
		if (args.length < 2) {
			printHelp();
			return;
		}
		
		CFG_FILE = args[0];
		
		int type = Type.A;
		int start = 1;
		if (args.length > 3 && args[1].equals("-t")) {
			type = Type.value(args[2]);
			if (type < 0)
				throw new IllegalArgumentException("invalid type");
			start = 3;
		}
		for (int i = start; i < args.length; i++) {
			Lookup l = new Lookup(args[i], type);
			l.run();
			printAnswer(args[i], l);
		}
	}
	
	public static void printHelp() {
		String output = "\nUSAGE:\n\n";
		output += "yoLookup <config-file> [-t] <name>\n\n";
		output += "\n--------------------------------------------------\n\n";
		System.out.println(output);
	}
	
	public static void printAnswer(String name, Lookup lookup) {
		//System.out.print(name + ":");
		int result = lookup.getResult();
		if (result != Lookup.SUCCESSFUL)
			System.out.print(" " + lookup.getErrorString());
		System.out.println();
		Name [] aliases = lookup.getAliases();
		if (aliases.length > 0) {
			System.out.print("# aliases: ");
			for (int i = 0; i < aliases.length; i++) {
				System.out.print(aliases[i]);
				if (i < aliases.length - 1)
					System.out.print(" ");
			}
			System.out.println();
		}
		if (lookup.getResult() == Lookup.SUCCESSFUL) {
			Record [] answers = lookup.getAnswers();
			for (int i = 0; i < answers.length; i++)
				System.out.println(answers[i]);
		}
	}
	
}
