package ch.deepimpact.crypto.test;
import java.util.concurrent.Callable;


public interface RecallableBruteForceTask extends Callable<String> {
	
	public RecallableBruteForceTask reset(char[] _beginning) ;

}
