package ch.deepimpact.crypto.test;

import java.io.BufferedInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BruteForceService {

	static String certPath;
	static int maxLength = 6;
	static int postfixLength = 4;
	static char min, max;
	static AtomicLong counter = new AtomicLong(0);
	static String result = null;
	
	public BruteForceService(char min, char max, int postFixLength, int maxLength, String certPath)
			throws InterruptedException, KeyStoreException,
			NoSuchProviderException, FileNotFoundException,
			NoSuchAlgorithmException, CertificateException, ExecutionException {

		Security.addProvider(new BouncyCastleProvider());

		BruteForceService.min = min;
		BruteForceService.max = max;
		BruteForceService.postfixLength = postFixLength;
		BruteForceService.maxLength = maxLength;
		BruteForceService.certPath = certPath;

	}

	public String solve(int nThreads) throws InterruptedException, ExecutionException,
			KeyStoreException, NoSuchProviderException, FileNotFoundException,
			NoSuchAlgorithmException, CertificateException {

		if (nThreads < 1)
			nThreads = Runtime.getRuntime().availableProcessors();
		System.out.println("Number of parallel threads: " + nThreads);
		ExecutorService executorService = Executors
				.newFixedThreadPool(nThreads);
		CompletionService<String> ecs = new ExecutorCompletionService<String>(
				executorService);

		List<Future<String>> futures = new ArrayList<Future<String>>(nThreads);
		List<RecallableBruteForceTask> tasks = new ArrayList<RecallableBruteForceTask>(
				nThreads);

		String result = null;
		char[] prefix = null;
		boolean forceClose = false;
		PrefixCounter prefixCounter = new PrefixCounter();
		long lasttime = System.nanoTime();
		long time = System.nanoTime();
		long lastCount = 0;
		long count = 0;
		long outercount = 0;
		float avgSpeed  = 0;
		try {
			for (int i = 0; i < nThreads; ++i) {
				prefix = prefixCounter.getVal();
				if (prefix != null) {
					tasks.add(new BruteForceTask(prefix));
					futures.add(ecs.submit(tasks.get(i)));
					if (!prefixCounter.increment()) {
						break;
					}
				}
			}
			while (true) {
				Future<String> next = ecs.take();
				result = next.get();
				if (result != null) {
					System.out.println("Password found: " + result);
					forceClose = true; // one password is enough.
					break;
				}
				for (int i = 0; i < nThreads; ++i) {
					if (futures.get(i) == next) {
						futures.set(
								i,
								ecs.submit(tasks.get(i).reset(
										prefixCounter.getVal())));
					}
				}
				time = System.nanoTime(); count = counter.longValue();
				float speed = ((count - lastCount) * 1000000000L / (time - lasttime));
				avgSpeed = (avgSpeed * outercount + speed) / (outercount + 1);
				if (outercount % nThreads == 0)  {
					System.out.println(avgSpeed + " pwd guesses / second average");
					
				}
				lasttime = time; lastCount = count; outercount++;
				if (!prefixCounter.increment()) {
					break;
				}
			}
		} finally {

			for (Future<String> f : futures)
				if (forceClose) {
					f.cancel(true);
				} else {
					f.get();
				}
		}
		System.out.println();
		System.out.print("Total false counts: " + counter + "     \r");
		return result;
	}

	private class PrefixCounter {

		private char[] chars;

		public PrefixCounter() {
			// Minimal size at start + one more element, to check for overflow.
			chars = new char[1 + 1];
			Arrays.fill(chars, 1, chars.length, min);
		}

		private boolean increment() {
			for (int i = chars.length - 1; i >= 0; i--) {
				if (chars[i] < max) {
					chars[i]++;
					break;
				}
				chars[i] = min;
			}
			if (chars[0] != 0) {
				// one more element, to check for overflow.
				if (chars.length < maxLength - postfixLength + 1) {
					chars = new char[chars.length + 1];
					Arrays.fill(chars, 1, chars.length, min);
				} else {
					return false;
				}
			}
			return true;

		}

		private char[] getVal() {
			return Arrays.copyOfRange(chars, 1, chars.length);
		}

	}

	private class BruteForceTask implements RecallableBruteForceTask {

		char[] password;
		char[] beginning;
		char[] chars;
		BufferedInputStream fis;
		KeyStore store;

		public BruteForceTask(char[] _beginning) throws KeyStoreException,
				NoSuchProviderException, FileNotFoundException,
				NoSuchAlgorithmException, CertificateException {
			beginning = _beginning;
			store = KeyStore.getInstance("PKCS12", "BC");
			fis = new BufferedInputStream(
					ClassLoader.getSystemResourceAsStream(certPath));
			fis.mark(128000);
			reset(_beginning);
		}

		private String iterateUntilFoundOrDone()
				throws NoSuchAlgorithmException, CertificateException,
				KeyStoreException {
			// loop over rest of password chars
			while (chars[0] == 0) {
				for (int i = 1; i < chars.length; i++) {
					password[beginning.length + i - 1] = chars[i];
				}
				if (doPassTest())
					return String.copyValueOf(password);
				increment();
			}
			return null;
		}

		private void increment() {
			for (int i = chars.length - 1; i >= 0; i--) {
				if (chars[i] < max) {
					chars[i]++;
					return;
				}
				chars[i] = min;
			}
		}

		private boolean doPassTest() throws NoSuchAlgorithmException,
				CertificateException, KeyStoreException {
			try {
				fis.reset();
				store.load(fis, password);
				result = String.copyValueOf(password); // happens once
				System.out.println("Wow! Password found:" + result);
				printStoreInfo();
				return true;
			} catch (IOException e) {
				counter.incrementAndGet();
				return false;
			}
		}

		public void printStoreInfo() throws KeyStoreException {
			Enumeration<String> en = store.aliases();
			while (en.hasMoreElements()) {
				String alias = (String) en.nextElement();
				System.out.println("found " + alias + ", isCertificate? "
						+ store.isCertificateEntry(alias));
			}

		}

		public String call() throws Exception {
			return iterateUntilFoundOrDone();
		}

		public RecallableBruteForceTask reset(char[] _beginning) {
			beginning = _beginning;
			// start after constant beginning
			password = Arrays.copyOf(_beginning, _beginning.length
					+ postfixLength);
			// fill rest with min
			Arrays.fill(password, _beginning.length, _beginning.length
					+ postfixLength - 1, (char) min);

			chars = new char[postfixLength + 1];
			Arrays.fill(chars, 1, chars.length, min);
			return this;
		}
	}

}