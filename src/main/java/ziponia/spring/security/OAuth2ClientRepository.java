package ziponia.spring.security;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2ClientRepository extends JpaRepository<ClientEntity, Integer> {

    ClientEntity findByClientId(String clientId);
}
