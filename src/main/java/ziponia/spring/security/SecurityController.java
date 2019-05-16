package ziponia.spring.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;

@Controller
public class SecurityController {

    @GetMapping(value = "/")
    public String home() {
        return "index";
    }

    @GetMapping(value = "/private")
    public String privatePage(Principal principal, Model model) {
        model.addAttribute("user", principal);
        return "private";
    }

    @GetMapping(value = "/public")
    public String publicPage() {
        return "public";
    }

    @GetMapping(value = "/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping(value = "/admin")
    public String adminPage() {
        return "admin";
    }

    @GetMapping(value = "/access_denied")
    public String access_denied_page() {
        return "access_denied";
    }

    /*@GetMapping(value = "/logout")
    public String logoutPage(HttpServletRequest req, HttpServletResponse res) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(req, res, auth);
        }

        return "redirect:/login";
    }*/

    @GetMapping(value = "/private/context")
    public String privateContextPage(
            @AuthenticationPrincipal Authentication authentication
    ) {

        SecurityContextHolder.getContext().getAuthentication(); // Authentication 을 반환

        System.out.println(authentication.getPrincipal());

        return "private";
    }
}
