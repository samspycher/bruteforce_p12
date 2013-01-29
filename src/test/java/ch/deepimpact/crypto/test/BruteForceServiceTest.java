package ch.deepimpact.crypto.test;

import junit.framework.Assert;

import org.junit.Test;

public class BruteForceServiceTest {

	@Test
	public void testSolve() {

		try {
			BruteForceService service = new BruteForceService('0', '9', 2, 4,
					"test.p12");
			Assert.assertEquals(service.solve(0), "1234");

			service = new BruteForceService('a', 'z', 2, 6,
					"test2.p12");
			Assert.assertEquals(service.solve(0), "tubeli");

		} catch (Exception e) {
			e.printStackTrace();
			Assert.fail();
		}
	}
}
