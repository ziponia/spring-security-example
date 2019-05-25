package ziponia.spring.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

@Controller
@RequiredArgsConstructor
public class UserController {

    @PersistenceContext
    private EntityManager em;

    private final UserRepository userRepository;

    @GetMapping(value = "/profile")
    public String userProfilePage(
            @RequestParam(required = false) String username,
            Model model
    ) {
        UserEntity user = null;

        if (username != null) {
            user = userRepository.findByUsername(username);
        }

        model.addAttribute("user", user);
        return "profile";
    }

    @PostMapping(value = "/profile/update")
    @PreAuthorize("isAuthenticated() and #entity.username == authentication.principal.username")
//    @PostAuthorize("isAuthenticated() and #entity.username == authentication.principal.username")
    public String userProfileUpdate(UserEntity entity) {
        UserEntity findUser = userRepository.findByUsername(entity.getUsername());
        findUser.setNickName(entity.getNickName());
        userRepository.save(findUser);
        System.out.println("SERVICE >>");
        return "redirect:/profile?username=" + findUser.getUsername();
    }

    @GetMapping(value = "/profile/group")
    @PreAuthorize("isAuthenticated()")
    public String myGroup(
            @AuthenticationPrincipal CustomUserDetail authentication,
            Model model
    ) {
        // user 정보를 가지고 온다.
        /*UserEntity user = em.createQuery("select u from UserEntity u where u.username = :username", UserEntity.class)
                .setParameter("username", authentication.getName()).getSingleResult();*/

        // group 정보를 가지고 온다.
        GroupEntity group = em.createQuery("select g from GroupEntity g where g.idx = :idx", GroupEntity.class)
                .setParameter("idx", authentication.getGroupIdx()).getSingleResult();

        model.addAttribute("group", group);

        return "user_group";
    }
}
