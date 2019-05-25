package ziponia.spring.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.ArrayList;
import java.util.List;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @PersistenceContext
    private EntityManager em; // JPA

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        List<UserEntity> findUsers = em
                .createQuery("select v from UserEntity v where v.username = :username", UserEntity.class)
                .setParameter("username", s)
                .getResultList();

        if (findUsers.size() == 0) {
            throw new UsernameNotFoundException("유저를 찾을 수 없습니다.");
        }

        UserEntity userEntity = findUsers.get(0);

        List<GrantedAuthority> authorities = new ArrayList<>();
        GrantedAuthority role = new SimpleGrantedAuthority("ROLE_USER");
        authorities.add(role);

        if (s.equals("admin")) {
            GrantedAuthority adminRole = new SimpleGrantedAuthority("ROLE_ADMIN");
            authorities.add(adminRole);
        }

        return new CustomUserDetail(userEntity.getUsername(), userEntity.getPassword(), authorities, userEntity.getGroup().getIdx());
    }
}
