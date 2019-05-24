package ziponia.spring.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class UserController {

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
}
