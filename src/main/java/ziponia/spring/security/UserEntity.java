package ziponia.spring.security;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.Date;

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

    private String nickName;

    @Enumerated(EnumType.STRING)
    private SocialProvider sns;

    private Date lastLogin;

    @ManyToOne(fetch = FetchType.LAZY)
    private GroupEntity group;
}
