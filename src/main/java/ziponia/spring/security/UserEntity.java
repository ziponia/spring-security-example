package ziponia.spring.security;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "tbl_users")
@Getter
@Setter
public class UserEntity {

    @Id
    @GeneratedValue
    private Integer idx;

    private String username;

    private String password;

    @Enumerated(EnumType.STRING)
    private SocialProvider sns;
}
