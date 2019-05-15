package ziponia.spring.security;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SecurityApplicationTests {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Test
	public void contextLoads() {
	}

	@Test
	public void passwordTest() {
		String password = "1234";
		String passwordEnc = passwordEncoder.encode(password);
		System.out.println(passwordEnc);
	}

}
