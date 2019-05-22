package ziponia.spring.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SecurityApplication {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private OAuth2ClientRepository oAuth2ClientRepository;

	@Autowired
	private UserRepository userRepository;

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	/*@Override
	public void run(String... args) throws Exception {

		UserEntity userEntity = userRepository.findByUsername("user");

		if (userEntity != null) {
			ClientEntity entity = new ClientEntity();
			entity.setIdx(1);
			entity.setClientId("client");
			entity.setClientSecret(passwordEncoder.encode("secret"));
			entity.setAuthorities("CLIENT");
			entity.setScope("read,basic,profile");
			entity.setGrantTypes("client_credentials,authorization_code,refresh_token,password");
			entity.setRedirectUri("http://localhost:4000/api/callback");
			entity.setAutoApprove(false);
			entity.setUserEntity(userEntity);
			oAuth2ClientRepository.save(entity);
		}
	}*/
}
