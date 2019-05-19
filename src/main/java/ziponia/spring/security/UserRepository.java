package ziponia.spring.security;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    UserEntity findByUsernameAndSns(String id, SocialProvider sns);
    UserEntity findByUsername(String username);
}
