package ziponia.spring.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class CustomUserDetail extends User {

    private Integer groupIdx;

    public CustomUserDetail(String username, String password, Collection<? extends GrantedAuthority> authorities, Integer groupIdx) {
        super(username, password, authorities);
        this.groupIdx = groupIdx;
    }

    public Integer getGroupIdx() {
        return groupIdx;
    }
}
