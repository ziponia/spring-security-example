package ziponia.spring.security;

import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.util.Date;
import java.util.List;

@Entity
@Getter
@Setter
@Table(name = "tbl_group")
public class GroupEntity {

    @Id
    @GeneratedValue
    private Integer idx;

    private String groupName;

    @OneToMany(mappedBy = "group")
    private List<UserEntity> users;

    @CreationTimestamp
    private Date createTime;

    @UpdateTimestamp
    private Date updateTime;
}
