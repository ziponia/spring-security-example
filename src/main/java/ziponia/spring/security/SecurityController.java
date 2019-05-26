package ziponia.spring.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Slf4j
@Controller
@RequiredArgsConstructor
public class SecurityController {

    private final AuthenticationManager authenticationManager;

    @GetMapping(value = "/")
    public String home() {
        return "index";
    }

    @GetMapping(value = "/private")
    public String privatePage(@AuthenticationPrincipal Authentication authentication, Model model) {
        boolean isOauth2User = authentication instanceof OAuth2Authentication;
        model.addAttribute("oauth2User", isOauth2User);
        if (!isOauth2User) {
            model.addAttribute("user", authentication);
        } else {
            OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;

            model.addAttribute("sUser", oAuth2Authentication.getUserAuthentication().getDetails());
        }
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

    //@GetMapping(value = "/access_denied")
    @RequestMapping(value = "/access_denied")
    public String access_denied_page() {
        return "access_denied";
    }

    @GetMapping(value = "/api/login")
    public String oauthLogin() {
        return "oauth_login";
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

    @PostMapping(value = "/my-login")
    public String customLoginProcess(
            @RequestParam String username,
            @RequestParam String password
    ) {
        // 아이디와 패스워드로, Security 가 알아 볼 수 있는 token 객체로 변경한다.
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        try {
            // AuthenticationManager 에 token 을 넘기면 UserDetailsService 가 받아 처리하도록 한다.
            Authentication authentication = authenticationManager.authenticate(token);
            // 실제 SecurityContext 에 authentication 정보를 등록한다.
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (DisabledException | LockedException | BadCredentialsException e) {
            String status;
            if (e.getClass().equals(BadCredentialsException.class)) {
                status = "invalid-password";
            } else if (e.getClass().equals(DisabledException.class)) {
                status = "locked";
            } else if (e.getClass().equals(LockedException.class)) {
                status = "disable";
            } else {
                status = "unknown";
            }
            return "redirect:/login?flag=" + status;
        }
        return "redirect:/";
    }
}
